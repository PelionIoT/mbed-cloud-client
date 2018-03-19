Mbed Platform Abstraction Layer (PAL)
=================

The Mbed Platform Abstraction Layer (PAL) connects Mbed Cloud Client with the underlying platform.

The main purpose of PAL is to enable easy and fast Mbed Cloud Client services portability, allowing them to operate over wide range of ARM Cortex-based platforms running different operating systems with various libraries (networking, for example).

PAL has two layers:

- **Service API layer**: provides the PAL APIs for Mbed Cloud Client code. The APIs are identical for all platforms and operating systems, and you should not modify them.
- **Platform API layer**: provides a standard set of baseline requirements for the platform. To allow Mbed Cloud Client to run on the target platform, you need to implement all requirements when you port. The implementation may be different for each target operating system or library; PAL provides reference implementations for several operating systems, including Mbed OS.

See the [Files](files.html) section to review documentation for specific APIs.

See the [full documentation and porting guide for PAL](/docs/v1.2/porting/index.html).

