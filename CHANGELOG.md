## Changelog for Pelion Device Management Client

### Release 2.1.1 (19.12.2018)

* Full support for asynchronous CoAP REST response with response code and payload for GET, PUT and POST requests. The feature is enabled via `ENABLE_ASYNC_REST_RESPONSE`.
* Updated Mbed CoAP to 4.7.2.

### Release 2.1.0 (11.12.2018)

#### Pelion Device Management Client

* Added Edge-specific translated device unregistration parameter `d` to registration message body.
* Start reconnection if no response received for CoAP ping.
* Updated Mbed CoAP to 4.7.1.

#### Factory configurator client

* Fixed SOTP flash write area size to accept values larger than 8 bytes.

#### Update Client

* Implemented new error codes for the campaign metrics feature.
* Client reports an error if the firmware image is greater than the device flash limit.
* Fixed issues with 32-bit addressing limits to enable download of very large firmware images.
* Removed an unnecessary DNS lookup. The HTTP Source FSM implementation redid the DNS lookup on every new fragment, even though in most cases the data was expected to already be in the TCP receive buffer. This modifies the FSM to avoid that step unless it is necessary.
* Added logic to generate a compilation error for an invalid download protocol value.
* Defined additional individually enabled trace functions at compile time to reduce the resume trace ROM size.
* Fixed various Linux warnings.
* Replaced wrong licence headers to Apache 2.0 and added license headers where missing.
* Removed dependency to deprecated component `COMMON_PAL` removed in Mbed OS 5.9.
* Guarded `ARM_UC_cryptoDecrypt` against unnecessary calls.
* Removed external reference to `arm_uc_blockdevice` and used default block device instance from Mbed OS instead.
* Added debug messages to check frequency of resume attempts.

#### Platform Adaptation Layer (PAL)

* Refactored internal library structure to allow more streamlined porting to new platforms.
* Removed limitation for setting page size for SOTP.

### Release 2.0.1 (12.10.2018)

#### Pelion Device Management Client

* Client now has CoAP duplication detection enabled by default, this improves stability of client on networks like NB-IoT.
* For resources containing big data (blockwise CoAP), client will start sending notifications only after subscription for that resource has completed its blockwise transfer.

#### Update Client

* Firmware download will now resume after network outage when using CoAP.
* Added support for slow link networks when a received packet contained only a HTTP header. This was causing the resume download feature to fail.

#### Platform Adaptation Layer (PAL)

* [Mbed OS] Change default mount point from "fs" to "default". Mount point "default" can be used with all diffrent type of storages.
* [Mbed OS][mbedtls] Tune software AES for smaller size instead of speed. Disable some of the speed optimizations on AES code to save 6 KB of ROM.
* [Mbed OS][mbedtls] mbedtls-config updates to save 7.5KB of ROM on Mbed OS.

### Release 2.0.0 (26.09.2018)

#### Pelion Device Management Client

* This version of client has been tested with Mbed OS 5.10.0.
* Updated Mbed CoAP to 4.6.3.

#### Factory configurator client

* Introducing certificate renewal feature for LWM2M as well as custom certificates.
  * LWM2M as well as custom certificate can be renewed through Certificate renewal service as well as from Client side APIs.

#### Platform Adaptation Layer (PAL)

* [Mbed OS] Fix hardfault under failure case of DNS request.

#### Update Client
* The firmware is downloaded using CoAP in MbedOS and HTTP in Linux.  
* Fixed segfault when Linux update scripts are provided but no header exists.
* Added support in HTTP source to make download fragments per burst user configurable.
* Fixed resume engine to not block on HTTP header errors.
* Fixed malloc issue in URI handling.
* Passed HTTP URI instead of coaps to the generate-manifest script.
* Fixed incorrect handling of async DNS callback which caused download failure.
* Fixed campaign not completing when payload hash mismatch introduced during firmware update operation. 


### Release 1.5.0 (11.09.2018)

#### Pelion Device Management Client

* Implement new callback to track notification and delayed post response delivery statuses.
  * Added API: `M2MBase::set_message_delivery_status_cb(message_delivery_status_cb callback, void *client_args);`
  * Following API's are mark as deprecated since this new API will replace them. These API's will be removed in subsequential client relases.
    * `M2MBase::send_notification_delivery_status(const M2MBase& object, const NotificationDeliveryStatus status)`
    * `M2MBase::get_notification_msgid()`
    * `M2MBase::set_notification_msgid(uint16_t msgid)`
    * `M2MBase::set_notification_delivery_status_cb(notification_delivery_status_cb callback, void *client_args)`
    * `M2MBase::get_notification_delivery_status()`
    * `M2MBase::clear_notification_delivery_status()`
* Implemented new functionality to get the internal object list of Mbed Cloud Client.
  * Added API: `MbedCloudClient::get_object_list()`.

#### Platform Adaptation Layer (PAL)

* Fixed Coverity issues in PAL.
* Improved error handling and logging for network and storage.
* Introduced `PAL_DNS_API_VERSION` for handling DNS.
  * 0 = synchronous DNS.
  * 1 = asynchronous DNS.
  * 2 = asynchronous DNS v2 (Only with Mbed OS 5.9 or later).
* Fixed PAL tracing implementation to allow an application to override the tracing level definitions.
* In `pal_isLeapYear` fixed a bug that made the certificate times off by a day.
* Enforced usage of MTU limits when using DTLS and `PAL_UDP_MTU_SIZE` is defined.
* Added configuration for K66F.
* [LINUX] Improved logging for RNG generation.
* [LINUX] Removed the glibc-specific function `pthread_sigqueue()` and replaced with `pthead_kill()`.
* [LINUX] Increased stack-size of `PAL_NOISE_TRNG_THREAD` to 32k. Increased stack-size of `PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE` to 24k.
* [LINUX] Added socket event filter clearing for `pal_plat_connect()` and `pal_plat_asynchronousSocket()`.
* [Mbed OS] Define `PAL_USE_INTERNAL_FLASH` and `PAL_INT_FLASH_NUM_SECTIONS = 2` by default for all targets.
* [Mbed OS] Compatibility changes for Mbed OS 5.10.
* [Mbed OS] Fixed a compatibility issue with Mbed TLS 2.13.0 for ARMCC compiler.

#### Mbed Cloud Update

* Fixed Device Management Client factory update flow by setting default identity configuration to KCM
* Added Firmware Update over CoAP into Device Management Client 
  * The firmware is downloaded using HTTP by default.
  * To Download using CoAP in MbedOS set the flag into "target_overrides" -section in mbed_app.json followingly:
    * "mbed-cloud-client.update-download-protocol": "MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL_COAP"
* [LINUX] Fixed Linux Update e2e failure reverting adding "set -eu" to linux scripts.
* Fixed RTL8195 Flash R/W Issue by adding FlashIAP Init -call into initialization
* Fixed long HTTP headers handling logic to support headers to split to multiple fragments
* Fixed Device Management Update Client versioning to work in factory flow
* Fixed Device Management Update Client uninitialization logic by adding handling for state ARM_UC_HUB_STATE_UNINITIALIZED in state machine
* Optimized static RAM usage by reusing the static object "ManifestManagerContext" during init
* Added support into Device Management Update Client Configuration to map external Download Protocol -definition to internal configurations. This is needed for supporting Download protocol selection in Device Management Client
* Implemented resume firmware download after connection failure.
* Added a scheduler trace macro.
* Merged two branches of Device Management Update client to one and added profile & feature flags to separate between different feature sets. New profile flag `ARM_UC_PROFILE_MBED_CLOUD_CLIENT` is used to enable correct profile for Device Management Client.
* `MBED_CONF_MBED_CLIENT_DNS_USE_THREAD` removed.
* Fixed Linux scripts to use -e and -u parameters for "set" to propagate errors
* Fixed Update state machine failure which was noticed when traces were enabled. Notification state machine was changed to sequentially wait internal asynchronous operations to complete before sending updated resource values to service and waiting for acknowledgment from service.
* MCCP=3 in Pelion Device Management Client: Support for sending update resource data as part of the Registration Message, thereby reducing traffic to Pelion Device Management.
* Changed uninitialization for Device Management Update Client to be done for all states past initialization states. Added null-checks for resource value settings.

#### Factory configurator client

* The error `FCC_STATUS_STORE_ERROR` is returned upon an internal storage init failure.

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

