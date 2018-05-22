/*
 * Copyright (c) 2015 - 2017 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Needed for PRIu64 on FreeRTOS
#include <stdio.h>
// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "mbed-client/m2mconnectionhandler.h"
#include "mbed-client-mbedtls/m2mconnectionsecuritypimpl.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-trace/mbed_trace.h"
#include "pal.h"
#include "m2mdevice.h"
#include "m2minterfacefactory.h"
#include <string.h>

#define TRACE_GROUP "mClt"

M2MConnectionSecurityPimpl::M2MConnectionSecurityPimpl(M2MConnectionSecurity::SecurityMode mode)
    :_init_done(M2MConnectionSecurityPimpl::INIT_NOT_STARTED),
     _conf(0),
     _ssl(0),
     _sec_mode(mode)
{
    memset(&_entropy, 0, sizeof(entropy_cb));
    memset(&_tls_socket, 0, sizeof(palTLSSocket_t));
}

M2MConnectionSecurityPimpl::~M2MConnectionSecurityPimpl()
{
    if(_ssl) {
        pal_freeTLS(&_ssl);
    }
    if(_conf) {
        pal_tlsConfigurationFree(&_conf);
    }
}

void M2MConnectionSecurityPimpl::reset()
{
    if(_ssl) {
        pal_freeTLS(&_ssl);
    }
    if(_conf) {
        pal_tlsConfigurationFree(&_conf);
    }
    _init_done = M2MConnectionSecurityPimpl::INIT_NOT_STARTED;
}

int M2MConnectionSecurityPimpl::init(const M2MSecurity *security, uint16_t security_instance_id)
{
    tr_debug("M2MConnectionSecurityPimpl::init");

    if(!security){
        tr_error("M2MConnectionSecurityPimpl Security NULL.");
        return -1;
    }

    if(_entropy.entropy_source_ptr) {
        if(PAL_SUCCESS != pal_addEntropySource(_entropy.entropy_source_ptr)){
            return -1;
        }
    }

    palTLSTransportMode_t mode = PAL_DTLS_MODE;
    if(_sec_mode == M2MConnectionSecurity::TLS){
        mode = PAL_TLS_MODE;
    }

    if(PAL_SUCCESS != pal_initTLSConfiguration(&_conf, mode)){
        tr_error("pal_initTLSConfiguration failed");
        return -1;
    }

    _init_done = M2MConnectionSecurityPimpl::INIT_CONFIGURING;


    if(_sec_mode == M2MConnectionSecurity::DTLS){
        // PAL divides the defined MAX_TIMEOUT by 2
        pal_setHandShakeTimeOut(_conf, MBED_CLIENT_DTLS_PEER_MAX_TIMEOUT*2);
    }

    M2MSecurity::SecurityModeType cert_mode =
        (M2MSecurity::SecurityModeType)security->resource_value_int(M2MSecurity::SecurityMode, security_instance_id);

    if( cert_mode == M2MSecurity::Certificate ){

        palX509_t owncert;
        palPrivateKey_t privateKey;
        palX509_t caChain;

        // Check if we are connecting to M2MServer and check if server and device certificates are valid, no need to do this
        // for Bootstrap or direct LWM2M server case
        if ((security->server_type(security_instance_id) == M2MSecurity::M2MServer) &&
            (security->get_security_instance_id(M2MSecurity::Bootstrap) >= 0) &&
            !check_security_object_validity(security, security_instance_id)) {
            tr_error("M2MConnectionSecurityPimpl::init - M2MServer certificate invalid or device certificate expired!");
            return -1;
        }

        owncert.size = 1 + security->resource_value_buffer(M2MSecurity::PublicKey, (const uint8_t*&)owncert.buffer, security_instance_id);
        privateKey.size = 1 + security->resource_value_buffer(M2MSecurity::Secretkey, (const uint8_t*&)privateKey.buffer, security_instance_id);
        caChain.size = 1 + security->resource_value_buffer(M2MSecurity::ServerPublicKey, (const uint8_t*&)caChain.buffer, security_instance_id);

        if(PAL_SUCCESS != pal_setOwnCertAndPrivateKey(_conf, &owncert, &privateKey)){
            tr_error("pal_setOwnCertAndPrivateKey failed");
            return -1;
        }
        if(PAL_SUCCESS != pal_setCAChain(_conf, &caChain, NULL)){
            tr_error("pal_setCAChain failed");
            return -1;
        }

    }else if(cert_mode == M2MSecurity::Psk){

        uint8_t *identity = NULL;
        uint32_t identity_len;
        uint8_t *psk = NULL;
        uint32_t psk_len;

        identity_len = security->resource_value_buffer(M2MSecurity::PublicKey, identity, security_instance_id);
        psk_len = security->resource_value_buffer(M2MSecurity::Secretkey, psk, security_instance_id);
        palStatus_t ret = pal_setPSK(_conf, identity, identity_len, psk, psk_len);
        free(identity);
        free(psk);

        if(PAL_SUCCESS != ret){
            tr_error("pal_setPSK failed");
            return -1;
        }

    }else{
        tr_error("Security mode not set");
        return -1;

    }

    if(PAL_SUCCESS != pal_initTLS(_conf, &_ssl)){
        tr_error("pal_initTLS failed");
        return -1;
    }

    if(PAL_SUCCESS != pal_tlsSetSocket(_conf, &_tls_socket)){
        tr_error("pal_tlsSetSocket failed");
        return -1;
    }

    _init_done = M2MConnectionSecurityPimpl::INIT_DONE;

#ifdef MBED_CONF_MBED_TRACE_ENABLE
    // Note: This call is not enough, one also needs the MBEDTLS_DEBUG_C to be defined globally
    // on build and if using default mbedtls configuration file, the
    // "#undef MBEDTLS_DEBUG_C" -line needs to be removed from mbedtls_mbed_client_config.h
    pal_sslSetDebugging(_conf, 1);
#endif

    tr_debug("M2MConnectionSecurityPimpl::init - out");
    return 0;
}

int M2MConnectionSecurityPimpl::start_handshake()
{
    tr_debug("M2MConnectionSecurityPimpl::start_handshake");

    palStatus_t ret;

    ret = pal_handShake(_ssl, _conf);

    if(ret == PAL_ERR_TLS_WANT_READ || ret == PAL_ERR_TLS_WANT_WRITE || ret == PAL_ERR_TIMEOUT_EXPIRED){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }
    else if(ret == PAL_ERR_TLS_PEER_CLOSE_NOTIFY) {
        return M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY;
    }

    if(ret != PAL_SUCCESS){ //We loose the original error here!
        tr_debug("M2MConnectionSecurityPimpl::start_handshake pal_handShake() error %" PRId32, ret);
        return -1;
    }

    ret = pal_sslGetVerifyResult(_ssl);
    if(PAL_SUCCESS != ret){
        tr_debug("M2MConnectionSecurityPimpl::start_handshake pal_sslGetVerifyResult() error %" PRId32, ret);
        return -1;
    }

    return ret;
}

int M2MConnectionSecurityPimpl::connect(M2MConnectionHandler* connHandler)
{
    tr_debug("M2MConnectionSecurityPimpl::connect");
    int ret = -1;

    if(M2MConnectionSecurityPimpl::INIT_DONE != _init_done){
        return ret;
    }

    ret = start_handshake();
    tr_debug("M2MConnectionSecurityPimpl::connect - handshake ret: %d", ret);
    return ret;
}


int M2MConnectionSecurityPimpl::send_message(unsigned char *message, int len)
{
    tr_debug("M2MConnectionSecurityPimpl::send_message");
    int ret = -1;
    palStatus_t return_value;
    uint32_t len_write;

    if(M2MConnectionSecurityPimpl::INIT_DONE != _init_done){
        return ret;
    }


    if(PAL_SUCCESS == (return_value = pal_sslWrite(_ssl, message, len, &len_write))){
        ret = (int)len_write;
    }
    else if(return_value == PAL_ERR_TLS_WANT_READ || return_value == PAL_ERR_TIMEOUT_EXPIRED){
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }
    else if(return_value == PAL_ERR_TLS_WANT_WRITE) {
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_WRITE;
    }
    else if(return_value == PAL_ERR_TLS_PEER_CLOSE_NOTIFY) {
        ret = M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY;
    }

    tr_debug("M2MConnectionSecurityPimpl::send_message - ret: %d", ret);
    return ret; //bytes written
}

int M2MConnectionSecurityPimpl::read(unsigned char* buffer, uint16_t len)
{
    int ret = -1;
    palStatus_t return_value;
    uint32_t len_read;

    if(M2MConnectionSecurityPimpl::INIT_DONE != _init_done){
        tr_error("M2MConnectionSecurityPimpl::read - init not done!");
        return ret;
    }

    if(PAL_SUCCESS == (return_value = pal_sslRead(_ssl, buffer, len, &len_read))){
        ret = (int)len_read;
    }

    else if(return_value == PAL_ERR_TLS_WANT_READ || return_value == PAL_ERR_TLS_WANT_WRITE || return_value == PAL_ERR_TIMEOUT_EXPIRED){
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }

    else if(return_value == PAL_ERR_TLS_PEER_CLOSE_NOTIFY) {
        ret = M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY;
    }

    return ret;
}

void M2MConnectionSecurityPimpl::set_random_number_callback(random_number_cb callback)
{
    (void)callback;
}

void M2MConnectionSecurityPimpl::set_entropy_callback(entropy_cb callback)
{

    _entropy = callback;

}

void M2MConnectionSecurityPimpl::set_socket(palSocket_t socket, palSocketAddress_t *address)
{
    _tls_socket.socket = socket;
    _tls_socket.socketAddress = address;
    _tls_socket.addressLength = sizeof(palSocketAddress_t);

    if(_sec_mode == M2MConnectionSecurity::TLS){
        _tls_socket.transportationMode = PAL_TLS_MODE;
    }
    else{
        _tls_socket.transportationMode = PAL_DTLS_MODE;
    }
}

bool M2MConnectionSecurityPimpl::certificate_parse_valid_time(const char *certificate, uint32_t certificate_len, uint64_t *valid_from, uint64_t *valid_to)
{
    palX509Handle_t cert = 0;
    size_t len;
    palStatus_t ret;

    tr_debug("certificate_validfrom_time");

    ret = pal_x509Initiate(&cert);
    if(PAL_SUCCESS != ret) {
        tr_error("certificate_validfrom_time - cert init failed: %u", (int)ret);
        pal_x509Free(&cert);
        return false;
    }
    if(PAL_SUCCESS != (ret = pal_x509CertParse(cert, (const unsigned char*)certificate, certificate_len))) {
        tr_error("certificate_validfrom_time - cert parse failed: %u", (int)ret);
        pal_x509Free(&cert);
        return false;
    }
    if(PAL_SUCCESS != (ret = pal_x509CertGetAttribute(cert, PAL_X509_VALID_FROM, valid_from, sizeof(uint64_t), &len))) {
        tr_error("certificate_validfrom_time - cert attr get failed: %u", (int)ret);
        pal_x509Free(&cert);
        return false;
    }
    if(PAL_SUCCESS != (ret = pal_x509CertGetAttribute(cert, PAL_X509_VALID_TO, valid_to, sizeof(uint64_t), &len))) {
        tr_error("certificate_validto_time - cert attr get failed: %u", (int)ret);
        pal_x509Free(&cert);
        return false;
    }

    pal_x509Free(&cert);
    return true;
}

bool M2MConnectionSecurityPimpl::check_security_object_validity(const M2MSecurity *security, uint16_t security_instance_id) {
    // Get time from device object
    M2MDevice *device = M2MInterfaceFactory::create_device();
    const uint8_t *certificate = NULL;
    int64_t device_time = 0;
    uint32_t cert_len = 0;

    if (device == NULL || security == NULL) {
        tr_error("No time from device object or security object available, fail connector registration %p, %p\n", device, security);
        return false;
    }

    // Get time from device object, returns -1 if resource not found
    device_time = device->resource_value_int(M2MDevice::CurrentTime, 0);

    tr_debug("Checking client certificate validity");

    // Get client certificate
    cert_len = security->resource_value_buffer(M2MSecurity::PublicKey, certificate, security_instance_id);
    if (cert_len == 0 || certificate == NULL) {
        tr_error("No certificate to check, return fail");
        return false;
    }

    if (device_time == -1 || !check_certificate_validity(certificate, cert_len, device_time)) {
        tr_error("Client certificate not valid!");
        return false;
    }
    return true;
}

bool M2MConnectionSecurityPimpl::check_certificate_validity(const uint8_t *cert, const uint32_t cert_len, const int64_t device_time)
{

    // Get the validFrom and validTo fields from certificate
    uint64_t server_validfrom = 0;
    uint64_t server_validto = 0;
    if(!certificate_parse_valid_time((const char*)cert, cert_len, &server_validfrom, &server_validto)) {
        tr_error("Certificate time parsing failed");
        return false;
    }

    tr_debug("M2MConnectionSecurityPimpl::check_certificate_validity - valid from: %" PRIu64, server_validfrom);
    tr_debug("M2MConnectionSecurityPimpl::check_certificate_validity - valid to: %" PRIu64, server_validto);
    // Cast to uint32_t since all platforms does not support PRId64 macro
    tr_debug("M2MConnectionSecurityPimpl::check_certificate_validity - device time: %" PRIu32, (uint32_t)device_time);

    if (device_time < (uint32_t)server_validfrom || device_time > (uint32_t)server_validto) {
        tr_error("Invalid certificate validity or device time outside of certificate validity period!");
        return false;
    }

    return true;
}

