## Changelog for Pelion Device Management Client

### Release 4.5.0 (04.06.2020)

#### Device Management Client

* Updated Mbed CoAP to v5.1.5.
* Fixed a bug that caused a transmission of a notification outside the threshold values after a registration update.
* Added support to define custom server URI port by application, `MBED_CLOUD_CLIENT_CUSTOM_URI_PORT` is build time optional parameter and is not set by default. When defined the client will connect to Cloud over this CoAP port rather than over one provided through factory or developer provisioned URI port.It is application's responsibility to ensure that the provided port is open on server side to accept incoming CoAP connection.
* Fixed client crash caused by wrong order of initializing event scheduler. As part of resource creation, there is a possibility that some of the resources can be created as Auto Observable, but that will require that those resources have certain base component like Timer to be created. Timer creation requires that event scheduler must have been created before hand. Since, Resource creation is an independent operation than instantiating Pelion Client, there is a chance that Resource can be created before Client stack is instantiated so it becomes highly dependant on order in which APIs are called. To resolve this issue, scheduler initilization call is also added in M2MBase constructor as fail-safe mechanism, so that order of API calls does not matter for application developer.
* Fixed the issue of reporting error callback of `MESSAGE_STATUS_SEND_FAILED` when notification sending fails because of network issue and internal CoAP retransmission fails.This is especially helpful for UDP and UDP-QUEUE based client where packets can be lost easily and should be informed to application for their booking purposes.
However, the notification will still be stored internally in client and it will attempt to re-send it on next successful reconnection to Pelion Cloud.
* Added a compile-time check to prevent configuring the client with LIFETIME values below 60 seconds. 60 seconds is the minimum allowed.
* [Mbed OS] Changed the default storage location for update to `ARM_UCP_FLASHIAP`.
* Added support for Device Sentry feature.

### Release 4.4.0 (17.04.2020)

* Changed the handling of numeric resources. Client now converts payloads to correct underlying data type. Previously, it allowed storing of `string-type` data in a resource with numeric data type.
* Fixed off-by-one bug in `m2mstring::convert_ascii_to_float()`.
* Deprecated and removed the usage of `PAL_UDP_MTU_SIZE`. The implementation was not correct and was not doing what it claimed to do. Applications should use instead `mbed-client-pal.pal-max-frag-len` to enable DTLS fragmentation support for network stacks with MTU limitations.
* Added KVStore library as a new component.
* Allow client to pause in any state.
* Client now cancels existing subscriptions after a full registration. This matches the server side behaviour for full registration, and ensures that notification tokens are properly synchronized.

### Factory Configuration Client

Bugfix: When a device with PSA configuration was restarted, the time was read before storage initialization. This caused rebootstrap of the device on every restart.

### Platform Adaptation Layer (PAL)

* Reintroduced backwards compatibility with Mbed OS 5.x releases to the PAL layer. String-based Mbed OS APIs are also supported in function `pal_plat_getNetInterfaceInfo`.
* Added support for NXP SDK.
* Added support for Renesas SDK.
* Flagged `pal_sslGetVerifyResult` and `pal_sslGetVerifyResultExtended` functions with `PAL_USE_SECURE_TIME` option. These functions rely on having the current time available and are not guaranteed to work without `PAL_USE_SECURE_TIME`.

### Release 4.3.0 (06.02.2020)

#### Device Management Client

* Updated Mbed CoAP to 5.1.3.
* Changed trace group so that all CoAP messages are visible in the [COAP] trace group.
* Fixed a double free error. In certain situations free was called twice for CoAP message payload.

### Platform Adaptation Layer (PAL)

* Fixed PAL filesystem API to allow access to files larger than 2GB. This allows update of images up to 4GB.
* [Crypto] Made entropy seeding check more robust.
* [Mbed OS] Removed dependency on string-based network API.

### Release 4.2.1 (20.12.2019)

Reverted a bug fix for PAL and FCC support for larger than 2 GB files. This fixes a regression in 4.2.0 release for embedded linux platforms where the application hardfaults when tracing is enabled.

### Release 4.2.0 (18.12.2019)

#### Device Management Client

* Fixed the handling of small blockwise sizes in delta update.
* Updated Mbed CoAP to 5.1.2.
* Notification tokens are cleared before a full registration.
  * Fixed an error that occurred in certain situations where subscriptions are lost and never come back until reboot.

### Platform Adaptation Layer (PAL)

* Added a developer feature to enable testing client in non-persistent RAM storage.
  * To enable the feature, define `PAL_SIMULATOR_FILE_SYSTEM_OVER_RAM 1`.
* Fixed PAL filesystem API to allow access to files larger than 2 GB.
* [Mbed OS] Added compatibility workaround for the DNS `Getaddrinfo` returning more than one address in future Mbed OS release.

### Release 4.1.0 (28.11.2019)

#### Device Management Client

* Deprecated `M2MFirmware` class.
* Fixed handling of the write attribute `step`. Previously, it did not store the value-change history correctly.
* Fixed compilation issues caused by disabled update features. Previously, update-related configuration was mandatory even if the feature itself was disabled.
* Removed support for the obsolete and undocumented write attribute `STP`. It was an alias for documented attribute `ST`.
* [Linux] Added missing internal sub-component dependencies to `CMakeLists.txt`.
* Added randomization to reconnection timer calculations.
* Increased the library default `MBED_CLOUD_CLIENT_LIFETIME` to 86400 seconds.

### Platform Adaptation Layer (PAL)

* Shortened one long filepath to mitigate compilation issues in Windows platforms due to too long file path.
* [Linux] Added `O_SYNC` flag for `pal_plat_fsOpen()` to ensure critical certificate data is written out without delays.
* TLS: Added an option to run Mbed TLS allocations in a static buffer.
* DTLS: Cancel DTLS timer event when cleaning up the TLS context.
  * In some cases, a DTLS timer event can remain in the running state even if the whole TLS context is destroyed.
  * This can happen, for example, when the client goes into a reconnect loop or when switching from bootstrap flow to LwM2M registration.

### Release 4.0.0 (25.09.2019)

#### Device Management Client

* Added a new API `init()` to `MbedCloudClient` class. You can use this optional API for two-phased memory allocation when initializing the client. It allows the example application to resolve out-of-memory issues during the initialization of the client library.
* Removed a redundant switch in `M2MFirmware` class `get_resource` function.
* Updated Mbed CoAP to 5.1.1.
* Fixed the Resource `/1/0/7` to return the correct binding mode when trying to `GET` the value of the Resource using a REST API call.
* Increased the Device Management Client initial reconnection delay to have range of 10 to 100 seconds.
* Increased the `MBED_CLIENT_TCP_KEEPALIVE_INTERVAL` to nine minutes.
* Implemented DTLS timer handling for handshake.
* When Device Management Client is compiled with the *PSA* configuration, it uses PSA-protected storage APIs instead of:
  * KVStore in Mbed OS.
  * ESFS/SOTP for non-Mbed OS platforms.

  <span class="notes">**Note:** Both storage types above are still used in the *non-PSA* variant of Device Management Client.</span>

#### Factory configurator client

* Support for UNISOC SXOS SDK v8p2.1 for UIS8908A NB-IoT board.

#### Platform Adaptation Layer (PAL)

* Improved support and proper timer logic for UDP/DTLS.
* PSA Crypto API v1.0b3 support.
* Support for UNISOC SXOS SDK v8p2.1 for UIS8908A NB-IoT board.

### Release 3.4.0 (28.08.2019)

#### Device Management Connect client

* Added the `max-age` option to be part of the notification message construction. This fixes the issue that the resource cache was not being updated due to value changes from notification messages.
* Added a Secure Device Access (SDA) client library.
* A new feature flag that enables SDA - `MBED_CLOUD_CLIENT_ENABLE_SDA` (disabled by default).
* A new feature flag, `MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS`, controls the usage of LwM2M Write attributes for LwM2M resources. Disabling this feature will allow you to save RAM used by observation parameters per resource. Disabled by setting the flag to 0.
* New API for managing update priority and rejecting optional firmware updates.
  - Added `set_update_authorize_priority_handler()`.
  - Added `update_reject()`.
  - New error enums for update authorization rejection, `UpdateWarningAuthorizationRejected`, `UpdateWarningAuthorizationUnavailable`.
* Support for certificate renewal with Platform Security Architecture (PSA).
* Extended `MbedCloudClient()` constructor to allow callback registration to client.
* A new API for creating `M2MResource` directly without first creating `M2MObject` and `M2MObjectInstance`.
* Bug fix: Requests sent from Device Management Client using the same URI and method were determined duplicates even if the context parameter was different.

#### Factory configurator client

* Replaced CBOR implementation library with tinycbor.
* Bug fix: Working with a file name length of `KCM_MAX_FILENAME_SIZE` in KCM APIs resulted in a `KCM_STATUS_FILE_NAME_TOO_LONG` error.

#### Secure Device Access client

* Initial Secure Device Access (SDA) release.
* SDA implements the ACE-OAuth standard, which specifies a framework for authenticating and authorizing in constrained IoT environments.
* The [full SDA documentation](../device-management/secure-device-access.html) is available on our documentation site.

#### Device Management Update client

* New update authorization API:
  * Deprecated `ARM_UC_SetAuthorizeHandler()` in favor of `ARM_UC_SetAuthorizePriorityHandler()`.
  * Added `ARM_UC_Reject()` to the application authorization callback to deliver the rejection reason to the service.
  * Added a priority field to the manifest.
  * Propagated update priority from the manifest to the application authorization callback.
* Writing of the update candidate metadata is postponed to a later phase. The metadata is written when the download has completed and the client application has authorized the installation.

#### Platform Adaptation Layer (PAL)

* [Linux] Read the source entropy from the target machine system environment if available; otherwise, use the user default source entropy file path.
  * Read the entropy file name from the system environment entry `ENTROPYSOURCE=<path-to-entropy-file-name>`.
* [TLS] Fixed potential double free issue in `pal_initTLS()`.
* [Tests] Do not try to execute filesystem tests if there is no filesystem.

### Release 3.3.0 (02.07.2019)

#### Device Management Connect client

* Updated Mbed CoAP to 4.8.0.
* A fix to accommodate a null terminator space for managing a common name parameter (max 64 characters) in an `X.509` certificate.
* Fix to clear stored SSL session when the device re-bootstraps otherwise the device is going into eternal re-bootstrap loop thus bricking up the device.

#### Factory configurator client

New `kcm_item_get_size_and_data` API - combines `kcm_item_get_data_size` and `kcm_item_get_data` into one synchronous API.

### Release 3.2.0 (12.06.2019)

#### Device Management Connect client

* Relaxed the enforcement of client configuration. Only `SN_COAP_MAX_BLOCKWISE_SIZE` is considered as a mandatory application configuration due to bootstrap and update (CoAP download) dependencies.
  * `LIFETIME` (default 3600 seconds), `ENDPOINT_TYPE` ("default") and `TRANSPORT_MODE` (default TCP) now have defaults. The application does not need to define them if default values are acceptable.
* Added new public APIs to the `MbedCloudClient` class to request Enrollment over Secure Transport (EST) (`est_request_enrollment`) and free the resulting certificate chain context (`est_free_cert_chain_context`).

#### Device Management Update client

* Added the delta update feature into Update client.
* Fixed HTTP download for very small files.
* Implemented a check to reject zero bytes firmware.
* Fixed installation authorization logic which was proceeding without waiting for the application callback.
* Fixed manifest manager to report correct error codes.
* Fixed PAL include files.
* Optimized flash and RAM footprint for CoAP source.
* Added a check to ensure that `SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE` is aligned with the storage page size.
* Added code to read the active firmware metadata header from file. This enables e-2-e testing with filesystem storage in a Linux host.
* Added heap and stack statistic trace messages.

#### Factory configurator client

* Naming restrictions for KCM APIs are now identical for KVStore and Pelion Secure Storage solutions (ESFS-SOTP):
  * `kcm_item_name` must only include characters `a`-`z`, `A`-`Z`, `0`-`9`, `_`, `-`, `.`.
  * The max `kcm_item_name` length is 100 bytes.
  * This deprecates Pelion Secure Storage naming restrictions.
* New APIs:
  * `kcm_asymmetric_sign` computes ECDSA raw signature on hash digest using associated private key name. Supports keys with EC SECP256R1 curve only.
  * `kcm_asymmetric_verify` verifies ECDSA raw signature on hash digest using associated private key name. Supports keys with EC SECP256R1 curve only.
  * `kcm_generate_random` generates a random number into a given buffer.
  * `kcm_ecdh_key_agreement` computes a shared secret using the elliptic curve Diffie Hellman algorithm.
* Fixed a bug in conversion of private key from DER to raw.
* `kcm_item_close_handle` receives a pointer to the handle instead of the handle. This is a bugfix for crash when `kcm_item_close_handle` is called twice.

#### Platform Adaptation Layer (PAL)

New cryptographic APIs implemented for PSA and non-PSA variants:

* `pal_parseECPrivateKeyFromHandle` parses EC private key from PAL private key handle.
* `pal_parseECPublicKeyFromHandle` parses EC public key from PAL public key handle.
* `pal_asymmetricSign` computes ECDSA raw signature of a previously hashed message. Supports keys with EC SECP256R1 curve only.
* `pal_asymmetricVerify` verifies the ECDSA raw signature of a previously hashed message. Supports keys with EC SECP256R1 curve only.
* `pal_ECDHKeyAgreement` computes raw shared secret key using elliptic curve Diffie–Hellman algorithm.

Other changes:

* Fixed unnessary dependencies to `SN_COAP_MAX_BLOCKWISE_SIZE` parameter.
* Added `pal_x509CertCheckExtendedKeyUsage` that checks the usage of certificate against `extended-key-usage` extension.
* [Linux] When creating threads, use the system provided `PTHREAD_STACK_MIN` as a minimum value. Previously, the application was allowed to define values smaller than the system-defined minimum.
* Implemented **SSL session resume** feature. This feature is enabled by default. Use the `PAL_USE_SSL_SESSION_RESUME` flag to control it.

### Yocto changes

* Removed the dependency of requiring Mbed CLI to be globally installed. This allows also virtualenv installations of Mbed CLI to work with the provided meta-layers.
  * Changed the meta-layer to use SSH authentication for Mbed CLI when needed. This is mostly needed when pulling in meta-layers from private repositories.
  * Changed the `meta-mbed-cloud-client.lib` file to use `https` format instead of `ssh`.

**Delta update related:**

* Modified application makefiles to call the new script for building a `tar` package of `rootfs`.
* Added the `build-raspberry-update-rootfs-tar.sh` script for building a `tar` package of `rootfs` contents to be used for delta purposes.
* Edited the local configuration sample and `fstab` to set `rootfs` into "read-only" mode so that delta firmware update can be applied into the device.
* Edited the Update client `metalayer recipe` to include the `Prepare` script in the image for delta processing.

### Release 3.1.1 (13.05.2019)

No changes.

### Release 3.1.0 (26.04.2019)

* Fixed client State machine for handling `pause()` handling. Fixes issues when `pause()` call was ignored when other operations were in effect.
* Implemented network status callback handling for client library. Now client will react to changes in network status callbacks to speed up client connection recovery during reconnection.
* Improved internal flagging of client library to enable further optimizations and modularization of client components.

#### Platform Adaptation Layer (PAL)

* Improved TLS configuration to optimize RAM usage.
* Improvement header include handling inside PAL layer.
* CMake improvements.
* Improvements for PAL unit tests.

### Release 3.0.0 (27.03.2019)

#### Device Management Connect client

* Disabled STL and Namespace pollution by default. These are deprecated features.
* [Mbed OS] Enabled secure storage feature (KVStore) by default.
* [Mbed OS] Disabled certificate enrollment features by default. You can enable them from application by setting `"mbed-cloud-client.disable-certificate-enrollment": null` in the `mbed_app.json` file. This saves 5.5 KB of flash.

#### Factory Configurator client

* Integration with PSA APIs.
* Factory Tool Communication Demo layer using asynchronous socket API.
* Bugfix for running with IAR8.32 compiler.

#### Device Management Update client

Added a temporary workaround for Cypress PSOC6 target to read each block from an external block device twice.

#### Platform Adaptation Layer (PAL)

* [Mbed OS] Added support for PSA-enabled Mbed TLS that is part of Mbed OS 5.12 release.
* Added new configuration flag for server socket APIs, `PAL_NET_SERVER_SOCKET_API`. The default is `1`.
   * For quick porting, set it to `0`. You do not need to implement `pal_plat_accept` and `pal_plat_listen`, which factory configurator client requires for the factory flow.
* Removed unused synchronous socket API implementation to reduce porting effort across different operating systems.
* Removed unused `PAL_NET_ASYNCHRONOUS_SOCKET_API` flag since there is only asynchronous socket implementation.
* Improved test coverage for platform tests.

### Release 2.2.1 (28.02.2019)

#### Device Management Connect client

* Fixed handling of blockwise message during concurrent notification sending.
* Fixed handling of content type format for PUT requests on resource level. Client only accepts `text/plain` and `opaque` content-types.

#### Factory Configurator client

* [Mbed OS] Support for injecting external entropy for devices using [KVstore](https://os.mbed.com/docs/mbed-os/v5.11/apis/kvstore.html) (internal flash).

#### Platform Adaptation Layer (PAL)

* [Mbed OS] Fixed the usage of deprecated socket APIs.
* Added logic to `pal_plat_initTime` to recover from data corruption due to power failure.
* Improved API documentation.
* [Mbed OS] Support for injecting external entropy for devices using [KVstore](https://os.mbed.com/docs/mbed-os/v5.11/apis/kvstore.html) (internal flash).

### Release 2.2.0 (25.02.2019)

#### Device Management Connect client

* Updated Mbed CoAP to 4.7.4.
    * Mbed CoAP for non-Mbed OS platforms is one patch release ahead of the Mbed OS version (5.11.3) of Mbed CoAP.
* Implemented DTLS fragmentation support for Device Management Client.
  * If your device has constraints with network buffer sizes where the DTLS handshake packets cannot fit into a single MTU, this configuration allows smaller packet size (minimum fragment length of 512 bytes + DTLS headers).
  * This feature is supported from Mbed TLS 2.15.1 onwards.
  * To enable support, define `mbed-client-pal.pal-max-frag-len = <value>` in the `mbed_app.json` file.
  * Value 0 = disabled, 1 = `MBEDTLS_SSL_MAX_FRAG_LEN_512`, 2= `MBEDTLS_SSL_MAX_FRAG_LEN_1024`, 3 = `MBEDTLS_SSL_MAX_FRAG_LEN_2048`.
  * The value must be twice the defined value of `SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE`, otherwise your client will give a compilation error with mismatching configuration options.
* [Edge] In Edge mode, the client can process more than one request per resource at a time.
* Fixed message status callback handling when using delayed response with the blockwise option.
    * Application received multiple delivered statuses when using blockwise transfer. This issue has now been resolved.
* [Linux] Updated CMake minimum version to 3.5.
* [Mbed OS] Enabled new configuration option for selecting secure storage mechanism : `"mbed-cloud-client.external-sst-support":"<null/1>"`
  * `"mbed-cloud-client.external-sst-support":null` means client continues using SOTP-ESFS based storage implementation.
  * `"mbed-cloud-client.external-sst-support":1` means client uses KVStore-based storage implementation. This requires Mbed OS 5.11.4 version and higher.
  * By default, it is set to `null` so older versions of Device Management Client example are binary compatible with this client version.
  * For Linux, client continues using SOTP-ESFS based storage implementation.
* Added a configuration check for the update profile (`ARM_UC_PROFILE_MBED_CLIENT_LITE`) to prevent accidental usage of LITE profile with Device Management Client.
* Added the [pause and resume functionality](../connecting/device-guidelines.html#client-pause-and-resume). The APIs let you change the network interface without deregistering the client. You can also pause the client, for example, for sleeping (with RAM retention).
* Deprecated client APIs that use `std::string`, including the whole `SimpleM2MResourceString` and `SimpleM2MResourceInt` classes.
    * The existing code using these APIs still compiles and works, but gives compiler warnings.
    * This was changed because the code using C++ Standard Template Library (STL) is causing issues in some environments, where the `std::` namespace or STL is not available at all.
    * STL also causes large ROM overhead, and disabling it saves ~15 KB on ROM budget, depending on the compiler toolchain used.
    * To remove the deprecated APIs completely, set `MBED_CLOUD_CLIENT_STL_API` to 0.
* You can now disable the namespace pollution of code that includes `MbedCloudClient.h` with `using namespace std;`.
  The behavior is left unchanged, but you can disable it by setting `MBED_CLOUD_CLIENT_STD_NAMESPACE_POLLUTION` to 0.
* Fixed regression on the application not receiving `value_updated()` callback for a POST message to an Object or Object Instance.
* Fixed stack overflow issue with local memory allocation from stack rather than heap when trying to read values from KCM.
* Changed network errors printing in `M2MConnectionHandlerpimpl.cpp` to use hexadecimal format for easier comparison with `mbed-client-pal/Source/PAL-Impl/Services-API/pal_errors.h`.
* Modified event API to use `uintptr_t` types for passing pointers instead of `uint32_t` for 64-bit compatibility.

#### Factory Configurator client

* Integration with Mbed OS 5.11 KVStore module.

#### Device Management Update client

* Support for large file download: converted notification handling to use a flag instead of a counter to avoid a deadlock in the scheduler.
* [Mbed OS] Enabled a new configuration option for selecting the storage location for the Update client update image.
  * `"mbed-cloud-client.update-storage":"<mode>"`
  * `<mode>` can be either `ARM_UCP_FLASHIAP` for internal flash or `ARM_UCP_FLASHIAP_BLOCKDEVICE` for external flash.
* Fixed the Update client state machine reboot state logic so that the active firmware details are not re-sent if reboot does not happen.
* Enabled a single HTTP request to be sent instead of multiple fragments during file download. Added a flag to guard the writing of the entire update file to pre-allocate space before the file is downloaded. The flag is disabled by default.
* Fixed traces from printing empty values for asynchronous DNS calls.
* Modified the trace and error macros in the manifest manager to use common macros.
* Fixed the race conditions on critical section code in the atomic-queue module.
* Fixed various compiler warnings.
* Update client calls a new `pal_plat_osGetRoT` function that reads RoT from KVStore.
* Added the possibility of queueing callbacks with an associated context in the Update client scheduler.
* Implemented an Update client scheduler API to post an error. The scheduler executes the error callback in priority over all the other callbacks in the queue.
* Added a compilation check for CoAP buffer size.
* Added trace messages to HTTP source module for debugging purposes.
* Fixed the Update client trace module when `mbed_trace` is off.
* Removed the accelerated handling of binary comparisons that relied on unaligned access.
* Fixed overflow in the HTTP request header.
* Sanitized module codes in trace messages. Defined a macro that replaces non-printable characters with a dot character. Wrapped module codes in the new macro wherever traces or debug messages are printed.
* Replaced calls to `mbed_tracef` with calls to `tr_debug`/`tr_error`.
* Added a compile time check for non-zero update storage size.
* Fixed page rounding issue in PAL block device.
* Improved trace messages in HTTP resume engine.
* Fixed the event API callback types to match the changes in Update client.
* Added support for reporting out of memory error from Mbed TLS.
* Removed `TRACE_GROUP` definitions from public header files.

#### Platform Adaptation Layer (PAL)

* Introduced PAL Secure Storage (SST) APIs.
  * Added Mbed OS configuration for secure storage using KVStore through this API (PAL SST).
* Added more unit tests and clarified error messages in them to help in-platform porting process.
* Added `PAL_UNIT_TESTING_NONSTANDARD_ENTRYPOINT` for executing unit tests.
* Added `pal_osSetRoT` API and related `pal_plat_osSetRoT` functions for SOTP and KVstore.
* Remove obsolete documentation and unnecessary board-specific configuration.
* Added error handling of `MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED`.
* Fixed error translation in the Linux implementation of `pal_plat_getAddressInfo`.
* Refactored the flash simulation over file system code out of the generic flash module.
* Refactored the Linux-specific reboot simulation code.

### Release 2.1.1 (19.12.2018)

* Full support for asynchronous CoAP REST response with response code and payload for GET, PUT and POST requests. You can enable this feature with `ENABLE_ASYNC_REST_RESPONSE`.
* Updated Mbed CoAP to 4.7.2.
* Added more unit tests and clarified error messages in them to help in platform porting process.

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
* Removed dependency to deprecated component `COMMON_PAL` in Mbed OS 5.9.
* Guarded `ARM_UC_cryptoDecrypt` against unnecessary calls.
* Removed external reference to `arm_uc_blockdevice` and used default block device instance from Mbed OS instead.
* Added debug messages to check the frequency of resume attempts.

#### Platform Adaptation Layer (PAL)

* Refactored internal library structure to allow more streamlined porting to new platforms.
* Removed limitation for setting page size for SOTP.
* PAL TLS: `memory allocation failed` error is passed to caller.
* The generated doxygen documentation has been removed from the repository. To generate the docs, use the `doxygen PAL_doxy` command in the `Docs` folder or see the [online documents](https://cloud.mbed.com/docs/current/pal/index.html).
* Fixed `pal_osGetDeviceKey()`'s return code on an invalid argument.
* RTOS: Refactored secure/weak time related code into new `Time` module.
* Time: Moved the SOTP-specific code out of `pal_time.c` to its own platform module.
* Unit test overhaul:
    * Tests are now split into smaller libraries.
    * Revived tests that were disabled by mistake.
    * Fixed uninitialized memory access bugs revealed by Valgrind.
    * Removed `ExampleBSP` code, that was used only by tests. Replaced it with common platform code provided in the [example application](https://github.com/ARMmbed/mbed-cloud-client-example/tree/master/source/platform).

### Release 2.0.1 (12.10.2018)

#### Pelion Device Management Client

* Client now has CoAP duplication detection enabled by default. This improves the stability of client on networks like NB-IoT.
* For resources containing big data (blockwise CoAP), client starts sending notifications only after subscription for that resource has completed its blockwise transfer.

#### Update Client

* Firmware download now resumes after network outage when using CoAP.
* Added support for slow link networks when a received packet contained only a HTTP header. This was causing the resume download feature to fail.

#### Platform Adaptation Layer (PAL)

* [Mbed OS] Changed default mount point from "fs" to "default". The mount point "default" can be used with all diffrent type of storages.
* [Mbed OS][Mbed TLS] Tuned software AES for smaller size instead of speed. Disabled some of the speed optimizations on AES code to save 6 KB of ROM.
* [Mbed OS][Mbed TLS] Updated mbedtls-config to save 7.5 KB of ROM on Mbed OS.

### Release 2.0.0 (26.09.2018)

#### Pelion Device Management Client

* This version of client has been tested with Mbed OS 5.10.0.
* Updated Mbed CoAP to 4.6.3.

#### Factory Configurator client

* Introduced certificate renewal feature for LwM2M and custom certificates.
  * You can renew both LwM2M and custom certificate through the Certificate renewal service and with client side APIs.

#### Platform Adaptation Layer (PAL)

* [Mbed OS] Fixed a hardfault in a failing DNS request.

#### Update client

* The firmware is downloaded using CoAP in MbedOS and HTTP in Linux.
* Fixed a segfault when Linux update scripts are provided but no header exists.
* Added support in HTTP source to make download fragments per burst user configurable.
* Fixed resume engine to not block on HTTP header errors.
* Fixed malloc issue in URI handling.
* Passed HTTP URI instead of coaps to the generate-manifest script.
* Fixed incorrect handling of an async DNS callback that caused a download failure.
* Fixed the error of a campaign not completing when there is a payload hash mismatch during the firmware update operation.


### Release 1.5.0 (11.09.2018)

#### Device Management Client

* Implemented a new callback to track notification and delayed post response delivery statuses.
  * Added API `M2MBase::set_message_delivery_status_cb(message_delivery_status_cb callback, void *client_args);`.
  * Following APIs are marked as deprecated since the new API replaces them. They will be removed in subsequential client relases:
    * `M2MBase::send_notification_delivery_status(const M2MBase& object, const NotificationDeliveryStatus status)`
    * `M2MBase::get_notification_msgid()`
    * `M2MBase::set_notification_msgid(uint16_t msgid)`
    * `M2MBase::set_notification_delivery_status_cb(notification_delivery_status_cb callback, void *client_args)`
    * `M2MBase::get_notification_delivery_status()`
    * `M2MBase::clear_notification_delivery_status()`
* Implemented a new functionality to get the internal Object list of Device Management Client.
  * Added API `MbedCloudClient::get_object_list()`.

#### Platform Adaptation Layer (PAL)

* Fixed Coverity issues in PAL.
* Improved error handling and logging for network and storage.
* Introduced `PAL_DNS_API_VERSION` for handling DNS.
  * 0 = synchronous DNS.
  * 1 = asynchronous DNS.
  * 2 = asynchronous DNS v2 (Only with Mbed OS 5.9 or later).
* Fixed PAL tracing implementation to allow an application to override the tracing level definitions.
* In `pal_isLeapYear`, fixed a bug that made the certificate times off by a day.
* Enforced usage of MTU limits when using DTLS and `PAL_UDP_MTU_SIZE` is defined.
* Added configuration for K66F.
* [LINUX] Improved logging for RNG generation.
* [LINUX] Removed the glibc-specific function `pthread_sigqueue()` and replaced it with `pthead_kill()`.
* [LINUX] Increased stack-size of `PAL_NOISE_TRNG_THREAD` to 32 k. Increased stack-size of `PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE` to 24 k.
* [LINUX] Added socket event filter clearing for `pal_plat_connect()` and `pal_plat_asynchronousSocket()`.
* [Mbed OS] Define `PAL_USE_INTERNAL_FLASH` and `PAL_INT_FLASH_NUM_SECTIONS = 2` by default for all targets.
* [Mbed OS] Compatibility changes for Mbed OS 5.10.
* [Mbed OS] Fixed a compatibility issue with Mbed TLS 2.13.0 for ARMCC compiler.

#### Update client

* Fixed Device Management Client factory update flow by setting the default identity configuration to KCM.
* Added firmware update over CoAP into Device Management Client.
  * The firmware is downloaded using HTTP by default.
  * To download with CoAP in Mbed OS, set the flag into `"target_overrides"` section in the `mbed_app.json` as follows:
    * "mbed-cloud-client.update-download-protocol": "MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL_COAP"
* [LINUX] Fixed Linux update e2e failure reverting by adding "set -eu" to the Linux scripts.
* Fixed RTL8195 Flash R/W issue by adding `FlashIAP Init` call into initialization.
* Fixed long HTTP headers handling logic to support headers to split to multiple fragments.
* Fixed Device Management Update client versioning to work in the factory flow.
* Fixed Device Management Update client uninitialization logic by adding handling for state `ARM_UC_HUB_STATE_UNINITIALIZED` in the state machine.
* Optimized static RAM usage by reusing the static object "ManifestManagerContext" during initialization.
* Added support to Device Management Update client configuration to map external download protocol definition to internal configurations. This is needed to support download protocol selection in Device Management Client.
* Implemented resume firmware download after a connection failure.
* Added a scheduler trace macro.
* Merged two branches of Device Management Update client to one and added profile and feature flags to separate between different feature sets. The new profile flag `ARM_UC_PROFILE_MBED_CLOUD_CLIENT` is used to enable correct profile for Device Management Client.
* `MBED_CONF_MBED_CLIENT_DNS_USE_THREAD` removed.
* Fixed Linux scripts to use `-e` and `-u` parameters for "set" to propagate errors
* Fixed an update state machine failure that was noticed when traces were enabled. The notification state machine was changed to sequentially wait for internal asynchronous operations to complete before sending updated resource values to service and waiting for an acknowledgment from service.
* MCCP=3 in Device Management Client: Support for sending update resource data as part of the registration message, thereby reducing traffic to Device Management.
* Changed uninitialization for Device Management Update client to be done for all states past initialization states. Added null-checks for resource value settings.

#### Factory Configurator client

* The error `FCC_STATUS_STORE_ERROR` is returned upon an internal storage init failure.

### Release 1.4.0 (13.07.2018)

* Fixed a timer initialization bug under connection handler.
* Linux: Updated mbed-coap to 4.5.0.
* This version of Cloud Client has been tested with Mbed OS 5.9.2.

#### Platform Adaptation Layer (PAL)

* Introduced support for ARIA cipher suite introduced in Mbed TLS 2.10.0.
* Introduced Mbed TLS configuration support for non-TRNG boards like NUCLEO-F411RE.
* Hook-up point for allowing application to provide its own reboot function.
  * Defining `PAL_USE_APPLICATION_REBOOT` activates this feature.
  * You must define the function `void pal_plat_osApplicationReboot(void)` in your application to provide the required functionality.
* Introduced the feature flag `PAL_USE_APPLICATION_REBOOT` for application to override generic reboot functionality, which is useful for different Linux flavors.
* New asynchronous DNS API (activated in application mbed_app.json via `mbed-client-pal.pal-dns-api-version : 2`) with Mbed OS 5.9.x.

#### Factory configurator client

* Chain verification failure results in `KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED` error instead of `FCC_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED`.
* Improved robustness of factory serial communication layer.
* Define `KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN` was renamed to `KCM_MAX_NUMBER_OF_CERTIFICATES_IN_CHAIN`.

#### Mbed Cloud Update

* Improved Linux shell scripts for compatibility and robustness.
* Fixed an issue in `ARM_UC_HUB_Initialize()` and `ARM_UC_HUB_Uninitialize()` to prevent these functions being called when Update client is in the wrong state.
* Fixed compiler warnings.
* Removed designated initialisers from C++ code.
* Update results are now sent synchronously to ensure that the Update client hub is in the correct state if several LwM2M operations are performed in rapid succession.
* Added error messages for missing commands in `arm_update_activate.sh`.
* Added error reporting when there is not enough space on the device to store the firmware image candidate.
* Added registration for the scheduler error handler.

#### PAL Platform

* Introduced Mbed TLS 2.10.0 support for ARIA cipher suite.

### Release 1.3.3 (08.06.2018)

#### Mbed Cloud Client

* Fixed issue: Wrong CoAP ping message. CoAP ping must be sent as an empty confirmable message.
* In the previous versions, the client in queue mode went to sleep while in reconnection mode. Now, it completes the connection before going to sleep.
* This version of Cloud Client supports Mbed OS 5.8.5 and onwards patch releases.
* Improvements for connection handler. Removed the usage of static pointer to class. It is now possible to allocate more than one class `M2MConnectionSecurityPimpl` in parallel.
* Support for new asynchronous DNS API ("mbed-client-pal.pal-dns-api-version : 2") with Mbed OS 5.9.x.

#### Factory Configurator client

* Full support for the `device generated keys` mode. You can activate the mode using the Factory Configurator Utility (FCU) or the KCM APIs.

    <span class="notes">**Note:** Cloud Client and Mbed Cloud do not yet support this mode.</span>
    
* A certificate signed request (CSR) that is generated on the device, can be created with the `Extended key usage` extension.
* A new KCM API introduced:
  * `kcm_certificate_verify_with_private_key` - a self-generated certificate can be checked against a stored private key.
* Fixed the `FtcdCommBase::wait_for_message` function to receive multiple messages.

#### Platform Adaptation Layer (PAL)

* The u-blox ODIN-W2 board now requires support for RSA crypto from Mbed TLS. RSA crypto has been enabled by default for the target `MODULE_UBLOX_ODIN_W2`. Enabling RSA crypto increases the flash size by 20 KB. More details in Mbed OS PR [#6963](https://github.com/ARMmbed/mbed-os/pull/6963).

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

* Fixed POST response handling. The client was sending multiple responses for the POST request received from Cloud, which would sometimes cause undefined behaviour for the POST callback on the webservice.

#### Mbed Cloud Update

* In Linux builds, Update related callbacks are now called in the context of the Update thread. Previously, it was possible to call some of these callbacks in a different thread.
* In Linux builds, if tracing is enabled, the update scheduler will display an error if a callback can't be added to the scheduler queue.

#### Platform Adaptation Layer (PAL)

* Linux: Replaced `fflush(NULL)` with `sync()` in `pal_osReboot` which was causing deadlock in Raspberry Pi3.

### Release 1.3.1 (19.04.2018)

#### Mbed Cloud Client

* Improved tracing of CoAP packages.
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

