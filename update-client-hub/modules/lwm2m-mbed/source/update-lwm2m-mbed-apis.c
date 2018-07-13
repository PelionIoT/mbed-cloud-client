#include "update-client-lwm2m/lwm2m-monitor.h"
#include "update-client-lwm2m/lwm2m-source.h"
#include "update-lwm2m-mbed-apis.h"


ARM_UPDATE_MONITOR ARM_UCS_LWM2M_MONITOR =
{
    .GetVersion           = ARM_UCS_LWM2M_MONITOR_GetVersion,
    .GetCapabilities      = ARM_UCS_LWM2M_MONITOR_GetCapabilities,
    .Initialize           = ARM_UCS_LWM2M_MONITOR_Initialize,
    .Uninitialize         = ARM_UCS_LWM2M_MONITOR_Uninitialize,

    .SendState            = ARM_UCS_LWM2M_MONITOR_SendState,
    .SendUpdateResult     = ARM_UCS_LWM2M_MONITOR_SendUpdateResult,
    .SendName             = ARM_UCS_LWM2M_MONITOR_SendName,
    .SendVersion          = ARM_UCS_LWM2M_MONITOR_SendVersion,

    .SetBootloaderHash    = ARM_UCS_LWM2M_MONITOR_SetBootloaderHash,
    .SetOEMBootloaderHash = ARM_UCS_LWM2M_MONITOR_SetOEMBootloaderHash
};

ARM_UPDATE_SOURCE ARM_UCS_LWM2M_SOURCE =
{
    .GetVersion             = ARM_UCS_LWM2M_SOURCE_GetVersion,
    .GetCapabilities        = ARM_UCS_LWM2M_SOURCE_GetCapabilities,
    .Initialize             = ARM_UCS_LWM2M_SOURCE_Initialize,
    .Uninitialize           = ARM_UCS_LWM2M_SOURCE_Uninitialize,
    .GetManifestDefaultCost = ARM_UCS_LWM2M_SOURCE_GetManifestDefaultCost,
    .GetManifestURLCost     = ARM_UCS_LWM2M_SOURCE_GetManifestURLCost,
    .GetFirmwareURLCost     = ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost,
    .GetKeytableURLCost     = ARM_UCS_LWM2M_SOURCE_GetKeytableURLCost,
    .GetManifestDefault     = ARM_UCS_LWM2M_SOURCE_GetManifestDefault,
    .GetManifestURL         = ARM_UCS_LWM2M_SOURCE_GetManifestURL,
    .GetFirmwareFragment    = ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment,
    .GetKeytableURL         = ARM_UCS_LWM2M_SOURCE_GetKeytableURL
};
