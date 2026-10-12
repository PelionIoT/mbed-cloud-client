# Unified desktop port validation

`port/macos-windows-merge-port` combines upstream master, `experiment/win10support`, and `port/macos-arm64`. The merge keeps the Linux PAL and includes both native desktop adapters. The library is validated through mbed-edge, which supplies its configuration and CMake integration.

The **Desktop port consumer checks** workflow checks the exact cloud-client commit selected by the workflow. Each job checks out a fixed mbed-edge revision, replaces only its cloud-client submodule checkout, records both revisions, and builds in a new directory. It does not install software, use cloud credentials, or sign release artifacts.

| Consumer | Fixed mbed-edge revision | Checks |
| --- | --- | --- |
| Linux master | `4bb547e6ef014ddb673eebeaa74eed7828b475d8` | Ubuntu 22.04 x64 production builds with mbedTLS and OpenSSL; BYOC, firmware updates enabled, FOTA disabled; command-line and dynamic-link smoke checks. |
| Linux regression suite | `4dd884af8746b63aaa26fa51aba1a5984074c2ba` | All six unit executables, with all tests required to run. This consumer includes the existing Linux mock-suite repairs. |
| macOS port | `4dd884af8746b63aaa26fa51aba1a5984074c2ba` | Native arm64 macOS 14 and 26, Debug and Release; static OpenSSL 3.5.9; Core, both PT libraries, provisioning, PAL, storage, networking, TLS, crypto, and AF_UNIX status tests. |
| Windows experiment | `b4180faa9221c0ec54f6e88871409c3733e2b37c` | Native Windows Server 2022 x64, Debug and Release; OpenSSL 3.5.9; production Core/provisioning build and Core/PAL tests. |

Linux production keeps firmware-update compilation enabled. The legacy update hub now includes the mbedTLS AES header only when its existing PSK manifest feature is enabled; the default public-key manifest profile does not use that header. This avoids an unnecessary mbedTLS dependency for the OpenSSL build without disabling firmware updates.

The pinned macOS Core consumer includes a vendor C++ header from inside a C linkage block. Xcode 15 on macOS 14 rejects the resulting standard-library templates. The workflow preincludes `cstddef` and `cstdarg` with `CMAKE_CXX_FLAGS` so this older consumer can test the library. Its source-level include correction belongs in the subsequent mbed-edge integration; this workaround must be removed when the consumer pin is updated to that correction.

Windows jobs use PowerShell 7 and explicitly check native command exit codes. This permits `nmake` to write its normal banner to stderr without treating successful compilation as a PowerShell exception.

Artifacts retain the selected commits, build logs, and test results for 14 days. These build and local runtime checks do not qualify real cloud enrollment, installer deployment, or all optional Linux feature combinations. The Linux master mock-suite profile is not used as the unit-test gate because that older consumer lacks the existing mock fixes; its unmodified production builds remain explicit gates.

After this cloud-client PR is merged, the mbed-edge integration should pin the accepted upstream commit and combine its current master with the Windows and macOS branches. Keep that later Core branch separate from this library integration.
