## Changelog for Mbed Cloud Client

### Release R1.3.1.1 (27.04.2018)

* Fixed POST response handling: The client was sending multiple responses for the POST request received from Cloud, which would sometimes cause undefined behaviour for the POST callback on the webservice.

#### Mbed Cloud Update

* In Linux builds, Update related callbacks are now called in the context of the Update thread. Previously, it was
  possible to call some of these callbacks in a different thread.
* In Linux builds, if tracing is enabled, the update scheduler will display an error if a callback can't
  be added to the scheduler queue.

#### Platform Adaptation Layer (PAL)

* Linux: Replaced `fflush(NULL)` with `sync()` in `pal_osReboot` which was causing deadlock in Raspberry Pi3.

### Release R1.3.1 (19.04.2018)

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

### Release R1.3.0 (27.3.2018)
* Initial public release.
