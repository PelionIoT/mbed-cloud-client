// Include bspatch source files, which are ignored with .mbedignore
// in order to avoid collision with the ones used in FOTA
// (due to the nature of mbed-os source file globbing)
#if defined(__MBED__) && !defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#include "../../../delta-tool-internal/source/bspatch.c"
#include "../../../delta-tool-internal/source/lz4.c"
#include "../../../delta-tool-internal/source/varint.c"
#endif
