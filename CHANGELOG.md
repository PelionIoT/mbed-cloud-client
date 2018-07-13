## Changelog for Mbed Cloud Client

### Release 1.4.0 (13.07.2018)
* Fixed a timer initialization bug under connection handler.
* Linux: Updated mbed-coap to 4.5.0.
* This version of Cloud Client has been tested with Mbed OS 5.9.2.

#### Platform Adaptation Layer (PAL)

* Introduced support for ARIA cipher suite introduced in mbedTLS 2.10.0.
* Introduced MbedTLS configuration support for non-TRNG boards like NUCLEO-F411RE.
* Hook-up point for allowing application to provide its own reboot function.
  * Defining `PAL_USE_APPLICATION_REBOOT` activates this feature.
  * You must define the function `void pal_plat_osApplicationReboot(void)` in your application to provide the required functionality.
* Introduced the feature flag `PAL_USE_APPLICATION_REBOOT` for application to override generic reboot functionality, which is useful for different Linux flavors.
* New asynchronous DNS API (activated in application mbed_app.json via `mbed-client-pal.pal-dns-api-version : 2`) with Mbed OS 5.9.x.

#### Factory configurator client

* Chain verification failure will result in `KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED` error instead of `FCC_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED`.
* Improved robustness of factory serial communication layer.
* Define `KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN` was renamed to `KCM_MAX_NUMBER_OF_CERTIFICATES_IN_CHAIN`.

#### Mbed Cloud Update

* Improved Linux shell scripts for compatibility and robustness.
* Fixed an issue in `ARM_UC_HUB_Initialize()` and `ARM_UC_HUB_Uninitialize()` to prevent these functions being called when Update client is in the wrong state.
* Fixed compiler warnings.
* Removed designated initialisers from C++ code.
* Update results are now sent synchronously to ensure that the Update Client hub is in the correct state if several LWM2M operations are performed in rapid succession.
* Added error messages for missing commands in `arm_update_activate.sh`.
* Added error reporting when there is not enough space on the device to store the firmware image candidate.
* Added registration for the scheduler error handler.

#### PAL Platform

* Introducing mbedTLS 2.10.0 support for ARIA cipher suite.

### Release 1.3.3 (08.06.2018)

#### Mbed Cloud Client

* Fixed issue: Wrong CoAP ping message. CoAP ping must be sent as an empty confirmable message.
* In the previous versions, the client in queue mode went to sleep while in reconnection mode. Now, it completes the connection before going to sleep.
* This version of Cloud Client supports Mbed OS 5.8.5 and onwards patch releases.
* Improvements for connection handler, removed usage of static pointer to class. There is now possible to allocate more than one class M2MConnectionSecurityPimpl pareller.
* Support for new asynchronous DNS API ("mbed-client-pal.pal-dns-api-version : 2") with Mbed OS 5.9.x. 

#### Factory configurator client

* Full support for the `device generated keys` mode. You can activate the mode using the factory configurator utility (FCU) or the KCM APIs.

    <span class="notes">**Note:** Cloud Client and Mbed Cloud do not yet support this mode.</span>
* A certificate signed request (CSR) that is generated on the device, can be created with the `Extended key usage` extension.
* A new KCM API introduced:
  * `kcm_certificate_verify_with_private_key` - a self-generated certificate can be checked against a stored private key.
* Fixed the `FtcdCommBase::wait_for_message` function to receive multiple messages.

#### Platform Adaptation Layer (PAL)

* The u-blox ODIN-W2 board now requires support for RSA crypto from Mbed TLS. RSA crypto has been enabled by default for the target `MODULE_UBLOX_ODIN_W2`. Enabling RSA crypto increases the flash size by 20KB. More details in Mbed OS PR [#6963](https://github.com/ARMmbed/mbed-os/pull/6963).

### Release 1.3.2 (22.05.2018)

#### Mbed Cloud Client

* Fixed issue: Resource does not notify with content format requested in observation.
* New internal API: `check_config_parameter()`, returns SUCCESS if parameter exits in KCM.
* Do not try to store Timezone/UTC data, if there is no data.
* A separate CoAP response is used only for POST operation, other ones are using piggybacked responses.
* Send only one notification at a time.
  * Fixes the issue with an application changing multiple resource values at a same time causing the client to lose notifications from earlier resources. This change ensures that the latest value is always sent to the server.
* Introducing Mbed Edge specific features:
  * M2MEndpoint class for describing endpoints behind Mbed Edge device.
  * Allow registering M2MEndpoints and M2MObjects using the registration API.
  * Added the `endpoint_type` attribute to the registration update message.
  * Added the `endpoint name` attribute to the registration and registration update messages.
* Improved Edge performance for registration update.
  * This optimization speeds up the registration update. It monitors which endpoints have changed and updates only
    them.
  * The bandwitdth of the CoAP messages is reduced. Endpoint data for the unchanged endpoints is not sent in the
    registration update.

#### Factory configurator client

* New APIs introduced for keys and CSR generation on the device:
  * `kcm_key_pair_generate_and_store`
  * `kcm_csr_generate`
  * `kcm_generate_keys_and_csr`
* Chain validations added.
  * A chain is validated when it is stored. Each certificate in the chain is validated against its issuer. An error is returned if the chain is not valid.
  * If the device certificate (bootstrap or LwM2M) or the update authentication certificate is saved as a chain, the expiration of all certificates is checked in the `fcc_verify_device_configured_4mbed_cloud` function.

#### Platform Adaptation Layer (PAL)

* Linux: Converted all timers to use signal-based timer (SIGEV_SIGNAL) instead of (SIGEV_THREAD).
  * This fixes the Valgrind warnings for possible memory leaks caused by LIBC's internal timer helper thread.

    <span class="notes">**Note**: If the client application is creating a pthread before instantiating MbedCloudClient,
    it needs to block the PAL_TIMER_SIGNAL from it. Otherwise the thread may get an exception caused
    by the default signal handler with a message such as "Process terminating with default action
    of signal 34 (SIGRT2)". For a suggested way to handle this please see `mcc_platform_init()` in [here](https://github.com/ARMmbed/mbed-cloud-client-example/blob/master/source/platform/Linux/common_setup.c).</span>
* Linux: Fixed the Linux-specific version of `pal_accept()'s` `addressLen` parameter which previously required a platform-specific socket address structure size, not a platform independent one.
* Fixed a hard fault issue that occurred when calling `pal_ECKeyGenerateKey`.
* Return PAL_ERR_BUFFER_TOO_SMALL if the output buffer is too small for write in `pal_writePrivateKeyToDer`, `pal_writePublicKeyToDer`  and `pal_x509CSRWriteDER APIs`.
* Fixed the missing handling for initialization failure of SOTP.
* New API `pal_x509CertGetHTBS`: Calculate the hash of the _To Be Signed_ part of an X509 certificate.

#### Mbed Cloud Update

* Improvements to the scheduler to ensure that events are not lost. The scheduler now uses a pool allocation mechanism and queue element locks.
* Implemented an API to get the active firmware details.
* A rollback protection error will now be reported as "Firmware update failed" (8) when MCCP=1.
* An error is issued when the firmware payload exceeds the maximum storage-size limit.
* Mbed Cloud Update now uses a constant time binary compare function.
* Fixed a build error for Cortex-A9 target when retrieving the current interrupt enabled state.

### Release 1.3.1.1 (27.04.2018)

#### Mbed Cloud Client

* Fixed POST response handling: The client was sending multiple responses for the POST request received from Cloud, which would sometimes cause undefined behaviour for the POST callback on the webservice.

#### Mbed Cloud Update

* In Linux builds, Update related callbacks are now called in the context of the Update thread. Previously, it was
  possible to call some of these callbacks in a different thread.
* In Linux builds, if tracing is enabled, the update scheduler will display an error if a callback can't
  be added to the scheduler queue.

#### Platform Adaptation Layer (PAL)

* Linux: Replaced `fflush(NULL)` with `sync()` in `pal_osReboot` which was causing deadlock in Raspberry Pi3.

### Release 1.3.1 (19.04.2018)

#### Mbed Cloud Client

* Improve tracing of CoAP packages.
* Added an API to enable sending of the resource value as a part of the registration message.
  * Only the following value types are allowed:
    * STRING
    * INTEGER
    * FLOAT
    * BOOLEAN
* A fix for sending an empty ACK with blockwise messages.
* Replaced TCP_KEEPALIVE with CoAP PING.
* Fixed the possible overflow in bootstrap errors.
* Now, a token is used to verify BS, register, update register and unregister responses.
* A fix for sending empty CoAP requests.
* A fix for the internal timer.
* PAL is used for asyncronous handling of DNS.

#### Mbed Cloud Update

Using PAL for asyncronous handling of DNS enables firmware update with mesh.

#### Platform Adaptation Layer (PAL)

* A fix to crash when enabling mbed-tls traces.
* Removed the thread-priority requirement.
* Fixed the compatibility issues with Mbed OS 5.8/5.9.

### Release 1.3.0 (27.3.2018)
* Initial public release.
