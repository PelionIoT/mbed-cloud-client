// Include bspatch source files, which are ignored with .mbedignore
// in order to avoid collision with the ones used in UC-Hub
// (due to the nature of mbed-os source file globbing)

#include "MbedCloudClientConfig.h"

#if (defined(__MBED__) || defined(__NANOSIMULATOR__)) && defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#include "bspatch/bspatch.c"
#include "bspatch/lz4.c"
#include "bspatch/varint.c"
#endif
