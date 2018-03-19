mbed Cloud Client API
=====================

This is the Doxygen generated API documentation of mbed Cloud Client. See the [Files](files.html) section to find the documentation about a specific API. It should be used together with the [mbed Cloud documentation](https://cloud.mbed.com/docs/latest).

The mbed Cloud Client high-level APIs allow mbed Cloud developers to create client side applications that connect to the mbed Cloud service, with LwM2M features as described in the [Lightweight Machine to Machine Technical Specification](http://technical.openmobilealliance.org/Technical/technical-information/release-program/current-releases/oma-lightweightm2m-v1-0).

mbed Cloud Client is an extension of the existing [mbed Client API](http://cloud.mbed.com/docs/v1.2/mbed-client/index.html). It provides an additional feature of creating a unique identity for the client on the Cloud service and also provides functionality to update Client's software through the mbed Cloud service.

- Use a factory flashed or developer credentials to create a unique device identity.
- Securely communicate with internet services over the industry standard TLS/DTLS.
- Manage devices on mbed Cloud service.
- Fully control the endpoint and application logic from the service side. 
- Provide functionality to update the devices over the air remotely controlled from the service side.
- Have a unified porting layer for porting to different platforms.

The API is in C++ to allow quick application development.
