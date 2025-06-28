/*
 * Copyright (c) 2015 - 2021 Pelion. All rights reserved.
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
#include "mbed-client/m2mconstants.h"
#include "pal.h"
#include "m2mdevice.h"
#include "m2minterfacefactory.h"

#include <string.h>
#include <stdio.h>
#include <string>

#define TRACE_GROUP "mClt"

M2MConnectionSecurityPimpl::M2MConnectionSecurityPimpl(M2MConnectionSecurity::SecurityMode mode)
    : _init_done(M2MConnectionSecurityPimpl::INIT_NOT_STARTED),
      _conf(0),
      _ssl(0),
      _sec_mode(mode),
      _network_rtt_estimate(10)    // Use reasonable initialization value for the RTT estimate. Must be larger than 0.
{
    memset(&_entropy, 0, sizeof(entropy_cb));
    memset(&_tls_socket, 0, sizeof(palTLSSocket_t));
}

M2MConnectionSecurityPimpl::~M2MConnectionSecurityPimpl()
{
    if (_ssl) {
        pal_freeTLS(&_ssl);
    }
    if (_conf) {
        pal_tlsConfigurationFree(&_conf);
    }
}

void M2MConnectionSecurityPimpl::reset()
{
    if (_ssl) {
        pal_freeTLS(&_ssl);
    }
    if (_conf) {
        pal_tlsConfigurationFree(&_conf);
    }
    _init_done = M2MConnectionSecurityPimpl::INIT_NOT_STARTED;
}

int M2MConnectionSecurityPimpl::init(const M2MSecurity *security, uint16_t security_instance_id, bool is_server_ping, const char *hostname)
{
    printf("DEBUG: M2MConnectionSecurityPimpl::init ENTRY - security_instance_id=%u, is_server_ping=%d\n", security_instance_id, is_server_ping);
    fflush(stdout);
    
    if (!security) {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - security is NULL\n");
        fflush(stdout);
        tr_error("M2MConnectionSecurityPimpl::init - security null");
        return M2MConnectionHandler::SSL_CONNECTION_ERROR;
    }

    printf("DEBUG: M2MConnectionSecurityPimpl::init - checking entropy\n");
    fflush(stdout);
    
    if (_entropy.entropy_source_ptr) {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - adding entropy source\n");
        fflush(stdout);
        if (PAL_SUCCESS != pal_addEntropySource(_entropy.entropy_source_ptr)) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_addEntropySource FAILED\n");
            fflush(stdout);
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;
        }
        printf("DEBUG: M2MConnectionSecurityPimpl::init - entropy source added successfully\n");
        fflush(stdout);
    }

    printf("DEBUG: M2MConnectionSecurityPimpl::init - setting TLS mode\n");
    fflush(stdout);
    
    palTLSTransportMode_t mode = PAL_DTLS_MODE;
    if (_sec_mode == M2MConnectionSecurity::TLS) {
        mode = PAL_TLS_MODE;
        printf("DEBUG: M2MConnectionSecurityPimpl::init - using TLS mode\n");
        fflush(stdout);
    } else {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - using DTLS mode\n");
        fflush(stdout);
    }

    printf("DEBUG: M2MConnectionSecurityPimpl::init - calling pal_initTLSConfiguration\n");
    fflush(stdout);
    
    if (PAL_SUCCESS != pal_initTLSConfiguration(&_conf, mode)) {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_initTLSConfiguration FAILED\n");
        fflush(stdout);
        tr_error("M2MConnectionSecurityPimpl::init - pal_initTLSConfiguration failed");
        return M2MConnectionHandler::SSL_CONNECTION_ERROR;
    }

    printf("DEBUG: M2MConnectionSecurityPimpl::init - TLS configuration initialized successfully\n");
    fflush(stdout);
    
    _init_done = M2MConnectionSecurityPimpl::INIT_CONFIGURING;
    
    printf("DEBUG: M2MConnectionSecurityPimpl::init - set state to INIT_CONFIGURING\n");
    fflush(stdout);

    // Store session into storage only in case of mds.
    // Otherwise first handshake against mds will fail.
#if (PAL_USE_SSL_SESSION_RESUME == 1)
    if (M2MSecurity::Bootstrap == security_instance_id) {
        pal_enableSslSessionStoring(_conf, false);
    } else {
        pal_enableSslSessionStoring(_conf, true);
    }
#endif

    if (_sec_mode == M2MConnectionSecurity::DTLS) {
        // convert to milliseconds and scale to reasonable range based on the network latency

        // add a bit of overhead for the initial timeout which is based on the round-trip estimate
        uint32_t dtls_min = _network_rtt_estimate * 1000 * 4 / 3;
        uint32_t dtls_max = dtls_min * 8;

        pal_setHandShakeTimeOut(_conf, dtls_min, dtls_max);
    }

    printf("DEBUG: M2MConnectionSecurityPimpl::init - getting security mode\n");
    fflush(stdout);
    
    M2MSecurity::SecurityModeType cert_mode =
        (M2MSecurity::SecurityModeType)security->resource_value_int(M2MSecurity::SecurityMode, security_instance_id);

    printf("DEBUG: M2MConnectionSecurityPimpl::init - cert_mode=%d (Certificate=%d, PSK=%d, EST=%d)\n", 
           cert_mode, M2MSecurity::Certificate, M2MSecurity::Psk, M2MSecurity::EST);
    fflush(stdout);

    if (cert_mode == M2MSecurity::Certificate || cert_mode == M2MSecurity::EST) {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - entering Certificate/EST mode\n");
        fflush(stdout);
        
        palX509_t owncert;
        palPrivateKey_t privateKey;
        palX509_t caChain;
        size_t len = MAX_CERTIFICATE_SIZE;
        uint8_t certificate[MAX_CERTIFICATE_SIZE];
        uint8_t *certificate_ptr = (uint8_t *)&certificate;
        size_t resource_buffer_size = MAX_CERTIFICATE_SIZE;

        printf("DEBUG: M2MConnectionSecurityPimpl::init - reading server public key (CA certificate)\n");
        fflush(stdout);
        
        int ret_code = security->resource_value_buffer(M2MSecurity::ServerPublicKey, certificate_ptr, security_instance_id, &resource_buffer_size);
        caChain.buffer = certificate_ptr;
        caChain.size = static_cast<uint32_t>(resource_buffer_size);

        printf("DEBUG: M2MConnectionSecurityPimpl::init - server public key read, ret_code=%d, size=%u\n", ret_code, caChain.size);
        fflush(stdout);

        if (ret_code < 0) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - failed to read server public key, ret_code=%d\n", ret_code);
            fflush(stdout);
            tr_error("M2MConnectionSecurityPimpl::init - failed to read public key");
            return M2MConnectionHandler::FAILED_TO_READ_CREDENTIALS;
        }

        printf("DEBUG: M2MConnectionSecurityPimpl::init - calling pal_setCAChain\n");
        fflush(stdout);
        
        if (PAL_SUCCESS != pal_setCAChain(_conf, &caChain, NULL)) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_setCAChain FAILED\n");
            fflush(stdout);
            tr_error("M2MConnectionSecurityPimpl::init - pal_setCAChain failed");
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;
        }
        
        printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_setCAChain SUCCESS\n");
        fflush(stdout);

        printf("DEBUG: M2MConnectionSecurityPimpl::init - reading secret key (private key)\n");
        fflush(stdout);
        
        ret_code = security->resource_value_buffer(M2MSecurity::Secretkey, certificate_ptr, security_instance_id, &len);

        printf("DEBUG: M2MConnectionSecurityPimpl::init - secret key read, ret_code=%d, len=%zu\n", ret_code, len);
        fflush(stdout);

        if (ret_code < 0) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - failed to read secret key, ret_code=%d\n", ret_code);
            fflush(stdout);
            tr_error("M2MConnectionSecurityPimpl::init - failed to read secret key");
            return M2MConnectionHandler::FAILED_TO_READ_CREDENTIALS;
        }

        printf("DEBUG: M2MConnectionSecurityPimpl::init - calling pal_initPrivateKey\n");
        fflush(stdout);
        
        if (pal_initPrivateKey(certificate_ptr, len, &privateKey) != PAL_SUCCESS) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_initPrivateKey FAILED\n");
            fflush(stdout);
            tr_error("M2MConnectionSecurityPimpl::init - pal_initPrivateKey failed");
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;
        }

        printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_initPrivateKey SUCCESS\n");
        fflush(stdout);
        
        printf("DEBUG: M2MConnectionSecurityPimpl::init - calling pal_setOwnPrivateKey\n");
        fflush(stdout);
        
        if (PAL_SUCCESS != pal_setOwnPrivateKey(_conf, &privateKey)) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_setOwnPrivateKey FAILED\n");
            fflush(stdout);
            tr_error("M2MConnectionSecurityPimpl::init - pal_setOwnPrivateKey failed");
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;
        }
        
        printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_setOwnPrivateKey SUCCESS\n");
        fflush(stdout);

#ifdef LWM2M_COMPLIANT
        // Use the public key resource instead of Chain resources that aren't part of the standard
        resource_buffer_size = MAX_CERTIFICATE_SIZE;
        ret_code = security->resource_value_buffer(M2MSecurity::PublicKey, certificate_ptr, security_instance_id, &resource_buffer_size);
        if (ret_code < 0) {
            tr_error("M2MConnectionSecurityPimpl::init - fail to read device certificate size");
            return M2MConnectionHandler::FAILED_TO_READ_CREDENTIALS;
        } else if (resource_buffer_size == 0) {
            tr_error("M2MConnectionSecurityPimpl::init - no device certificate!");
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;
        } else {
            owncert.size = static_cast<uint32_t>(resource_buffer_size);
            owncert.buffer = certificate_ptr;
            if (PAL_SUCCESS != pal_setOwnCertChain(_conf, &owncert)) {
                tr_error("M2MConnectionSecurityPimpl::init - pal_setOwnCertChain failed");
                return M2MConnectionHandler::SSL_CONNECTION_ERROR;
            }
        }
#else

        printf("DEBUG: M2MConnectionSecurityPimpl::init - entering certificate chain mode\n");
        fflush(stdout);
        
        // Open certificate chain, size parameter contains the depth of certificate chain
        size_t cert_chain_size = 0;
        
        printf("DEBUG: M2MConnectionSecurityPimpl::init - opening certificate chain\n");
        fflush(stdout);
        
        if (security->resource_value_buffer_size(M2MSecurity::OpenCertificateChain, security_instance_id, &cert_chain_size) < 0) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - failed to open certificate chain\n");
            fflush(stdout);
            tr_error("M2MConnectionSecurityPimpl::init - fail to open certificate chain!");
            return M2MConnectionHandler::FAILED_TO_READ_CREDENTIALS;
        } else if (cert_chain_size == 0) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - certificate chain size is 0\n");
            fflush(stdout);
            tr_error("M2MConnectionSecurityPimpl::init - no certificate!");
            security->resource_value_buffer_size(M2MSecurity::CloseCertificateChain, security_instance_id, &cert_chain_size);
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;
        } else {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - certificate chain opened successfully, size=%zu\n", cert_chain_size);
            fflush(stdout);
            tr_info("M2MConnectionSecurityPimpl::init - cert chain length: %lu", (unsigned long)cert_chain_size);
            size_t index = 0;

            while (index < cert_chain_size) {
                size_t resource_buffer_size = MAX_CERTIFICATE_SIZE;

                ret_code = security->resource_value_buffer(M2MSecurity::ReadDeviceCertificateChain, certificate_ptr, security_instance_id, &resource_buffer_size);
                owncert.buffer = certificate_ptr;

                if (ret_code < 0) {
                    tr_error("M2MConnectionSecurityPimpl::init - failed to read device certificate");
                    return M2MConnectionHandler::FAILED_TO_READ_CREDENTIALS;
                }
                owncert.size = static_cast<uint32_t>(resource_buffer_size);
                if (PAL_SUCCESS != pal_setOwnCertChain(_conf, &owncert)) {
                    tr_error("M2MConnectionSecurityPimpl::init - pal_setOwnCertChain failed");
                    security->resource_value_buffer_size(M2MSecurity::CloseCertificateChain, security_instance_id, &cert_chain_size);
                    return M2MConnectionHandler::SSL_CONNECTION_ERROR;
                }

                index++;
            }
            security->resource_value_buffer_size(M2MSecurity::CloseCertificateChain, security_instance_id, &cert_chain_size);
        }
#endif //LWM2M_COMPLIANT
    } else if (cert_mode == M2MSecurity::Psk) {

        uint8_t identity[MAX_CERTIFICATE_SIZE];
        uint8_t *identity_ptr = (uint8_t *)&identity;
        size_t identity_len = MAX_CERTIFICATE_SIZE;
        uint8_t psk[MAX_CERTIFICATE_SIZE];
        uint8_t *psk_ptr = (uint8_t *)&psk;
        size_t psk_len = MAX_CERTIFICATE_SIZE;

        int ret_code = security->resource_value_buffer(M2MSecurity::PublicKey, identity_ptr, security_instance_id, &identity_len);
        if (ret_code < 0) {
            tr_error("M2MConnectionSecurityPimpl::init -  failed to read PSK identity");
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;
        }

        ret_code = security->resource_value_buffer(M2MSecurity::Secretkey, psk_ptr, security_instance_id, &psk_len);
        if (ret_code < 0) {
            tr_error("M2MConnectionSecurityPimpl::init -  failed to read PSK key");
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;;
        }

        palStatus_t ret = pal_setPSK(_conf, identity_ptr, static_cast<uint32_t>(identity_len), psk_ptr, static_cast<uint32_t>(psk_len));

        if (PAL_SUCCESS != ret) {
            tr_error("M2MConnectionSecurityPimpl::init  - pal_setPSK failed");
            return M2MConnectionHandler::SSL_CONNECTION_ERROR;;
        }

    } else {
        tr_error("M2MConnectionSecurityPimpl::init - security mode not set");
        return M2MConnectionHandler::SSL_CONNECTION_ERROR;
    }

    printf("DEBUG: M2MConnectionSecurityPimpl::init - calling pal_initTLS\n");
    fflush(stdout);
    
    if (PAL_SUCCESS != pal_initTLS(_conf, &_ssl, is_server_ping)) {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_initTLS FAILED\n");
        fflush(stdout);
        tr_error("M2MConnectionSecurityPimpl::init - pal_initTLS failed");
        return M2MConnectionHandler::SSL_CONNECTION_ERROR;
    }

    printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_initTLS SUCCESS\n");
    fflush(stdout);
    
    printf("DEBUG: M2MConnectionSecurityPimpl::init - calling pal_tlsSetSocket\n");
    fflush(stdout);
    
    if (PAL_SUCCESS != pal_tlsSetSocket(_conf, &_tls_socket)) {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_tlsSetSocket FAILED\n");
        fflush(stdout);
        tr_error("M2MConnectionSecurityPimpl::init - pal_tlsSetSocket failed");
        return M2MConnectionHandler::SSL_CONNECTION_ERROR;
    }

    printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_tlsSetSocket SUCCESS\n");
    fflush(stdout);
    
    // Set SNI hostname if provided
    if (hostname && strlen(hostname) > 0) {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - Setting SNI hostname: '%s'\n", hostname);
        fflush(stdout);
        
        // Extract just the hostname part (remove port if present)
        std::string hostname_str(hostname);
        size_t colon_pos = hostname_str.find(':');
        if (colon_pos != std::string::npos) {
            hostname_str = hostname_str.substr(0, colon_pos);
        }
        
        printf("DEBUG: M2MConnectionSecurityPimpl::init - Extracted hostname: '%s'\n", hostname_str.c_str());
        fflush(stdout);
        
        // Call PAL to set SNI hostname (we'll add this to PAL layer)
        if (PAL_SUCCESS != pal_setSNIHostname(_ssl, hostname_str.c_str())) {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_setSNIHostname FAILED for hostname '%s'\n", hostname_str.c_str());
            fflush(stdout);
            tr_warn("M2MConnectionSecurityPimpl::init - pal_setSNIHostname failed for hostname '%s'", hostname_str.c_str());
            // Don't fail completely, just log warning since SNI is not always critical
        } else {
            printf("DEBUG: M2MConnectionSecurityPimpl::init - pal_setSNIHostname SUCCESS for hostname '%s'\n", hostname_str.c_str());
            fflush(stdout);
            tr_info("M2MConnectionSecurityPimpl::init - SNI hostname set to '%s'", hostname_str.c_str());
        }
    } else {
        printf("DEBUG: M2MConnectionSecurityPimpl::init - No hostname provided for SNI\n");
        fflush(stdout);
    }
    
    _init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    
    printf("DEBUG: M2MConnectionSecurityPimpl::init - set state to INIT_DONE\n");
    fflush(stdout);

#if MBED_CONF_MBED_TRACE_ENABLE
    // Note: This call is not enough, one also needs the MBEDTLS_DEBUG_C to be defined globally
    // on build and if using default mbedtls configuration file, the
    // "#undef MBEDTLS_DEBUG_C" -line needs to be removed from mbedtls_mbed_client_config.h
    pal_sslSetDebugging(_conf, 1);
#endif

    printf("DEBUG: M2MConnectionSecurityPimpl::init - COMPLETE SUCCESS, returning ERROR_NONE\n");
    fflush(stdout);
    
    return M2MConnectionHandler::ERROR_NONE;
}

int M2MConnectionSecurityPimpl::connect(M2MConnectionHandler * /*connHandler*/, bool is_server_ping)
{
    palStatus_t ret = PAL_SUCCESS;
    if (is_server_ping) {
        tr_info("M2MConnectionSecurityPimpl::connect is SERVER PING");
        ret = pal_handShake(_ssl, _conf, true);
    } else {
        tr_debug("M2MConnectionSecurityPimpl::connect is normal HANDSHAKE");
        ret = pal_handShake(_ssl, _conf, false);
    }

    tr_debug("M2MConnectionSecurityPimpl::connect return code  %" PRIx32, ret);

    if (ret == PAL_SUCCESS) {
        return M2MConnectionHandler::ERROR_NONE;
    } else if (ret == PAL_ERR_TLS_WANT_READ || ret == PAL_ERR_TLS_WANT_WRITE) {
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    } else if (ret == PAL_ERR_TLS_PEER_CLOSE_NOTIFY) {
        return M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY;
    } else if (ret == PAL_ERR_NO_MEMORY) {
        return M2MConnectionHandler::MEMORY_ALLOCATION_FAILED;
    } else if (ret == PAL_ERR_TLS_CLIENT_RECONNECT) {
        return M2MConnectionHandler::SOCKET_READ_ERROR;
    } else if (ret == PAL_ERR_X509_CERT_VERIFY_FAILED || ret == PAL_ERR_SSL_FATAL_ALERT_MESSAGE) {
        return M2MConnectionHandler::SSL_HANDSHAKE_ERROR;
    } else if (ret == PAL_ERR_TIMEOUT_EXPIRED || ret == PAL_ERR_TLS_TIMEOUT) {
        return M2MConnectionHandler::SOCKET_TIMEOUT;
    } else {
        // All other errors will result in reconnection.
        return M2MConnectionHandler::SOCKET_READ_ERROR;
    }
}

int M2MConnectionSecurityPimpl::send_message(unsigned char *message, int len)
{
    int ret = M2MConnectionHandler::SOCKET_SEND_ERROR;
    palStatus_t return_value;
    uint32_t len_write;

    if (PAL_SUCCESS == (return_value = pal_sslWrite(_ssl, _conf, message, len, &len_write))) {
        ret = (int)len_write;
    } else if (return_value == PAL_ERR_TLS_WANT_READ || return_value == PAL_ERR_TIMEOUT_EXPIRED) {
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    } else if (return_value == PAL_ERR_TLS_WANT_WRITE) {
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_WRITE;
    } else if (return_value == PAL_ERR_TLS_PEER_CLOSE_NOTIFY) {
        ret = M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY;
    } else if (return_value == PAL_ERR_NO_MEMORY) {
        ret = M2MConnectionHandler::MEMORY_ALLOCATION_FAILED;
    } else if (return_value == PAL_ERR_TIMEOUT_EXPIRED || return_value == PAL_ERR_TLS_TIMEOUT) {
        return M2MConnectionHandler::SOCKET_TIMEOUT;
    }

    tr_debug("M2MConnectionSecurityPimpl::send_message - ret: %d", ret);
    return ret; //bytes written or error
}

int M2MConnectionSecurityPimpl::read(unsigned char *buffer, uint16_t len)
{
    int ret = M2MConnectionHandler::SOCKET_READ_ERROR;
    palStatus_t return_value;
    uint32_t len_read;

    if (PAL_SUCCESS == (return_value = pal_sslRead(_ssl, buffer, len, &len_read))) {
        ret = (int)len_read;
    } else if (return_value == PAL_ERR_TLS_WANT_READ || return_value == PAL_ERR_TLS_WANT_WRITE || return_value == PAL_ERR_TIMEOUT_EXPIRED) {
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    } else if (return_value == PAL_ERR_TLS_PEER_CLOSE_NOTIFY) {
        ret = M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY;
    } else if (return_value == PAL_ERR_NO_MEMORY) {
        ret = M2MConnectionHandler::MEMORY_ALLOCATION_FAILED;
    } else if (return_value == PAL_ERR_TIMEOUT_EXPIRED || return_value == PAL_ERR_TLS_TIMEOUT) {
        return M2MConnectionHandler::SOCKET_TIMEOUT;
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

    if (_sec_mode == M2MConnectionSecurity::TLS) {
        _tls_socket.transportationMode = PAL_TLS_MODE;
    } else {
        _tls_socket.transportationMode = PAL_DTLS_MODE;
    }
    
    tr_info("M2MConnectionSecurityPimpl::set_socket - transportationMode set to %d (TLS=%d, DTLS=%d), socket=%p", 
            _tls_socket.transportationMode, PAL_TLS_MODE, PAL_DTLS_MODE, (void*)&_tls_socket);
}

int M2MConnectionSecurityPimpl::set_dtls_socket_callback(void(*foo)(void *), void *argument)
{
    pal_setDTLSSocketCallback(_conf, (palSocketCallback_f)foo, argument);
    return M2MConnectionHandler::ERROR_NONE;
}

void M2MConnectionSecurityPimpl::update_network_rtt_estimate(uint8_t rtt_estimate)
{
    _network_rtt_estimate = rtt_estimate;
}

void M2MConnectionSecurityPimpl::store_cid()
{
    pal_store_cid();
}

void M2MConnectionSecurityPimpl::remove_cid()
{
    pal_remove_cid();
}

bool M2MConnectionSecurityPimpl::is_cid_available()
{
    return pal_is_cid_available();
}

void M2MConnectionSecurityPimpl::set_cid_value(const uint8_t *data_ptr, const size_t data_len)
{
    pal_set_cid_value(_ssl, _conf, data_ptr, data_len);
}
