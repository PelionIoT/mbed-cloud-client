//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2016 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#include "arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE) && (ARM_UC_FEATURE_PAL_BLOCKDEVICE == 1)

#include "update-client-paal/arm_uc_paal_update_api.h"

#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice_implementation.h"
#include "update-client-pal-flashiap/arm_uc_pal_flashiap_implementation.h"

/**
 * @brief Initialize the underlying storage and set the callback handler.
 *
 * @param callback Function pointer to event handler.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UCP_FashIAP_BlockDevice_Initialize(ARM_UC_PAAL_UPDATE_SignalEvent_t callback)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (callback) {
        arm_uc_error_t status1 = ARM_UC_PAL_FlashIAP_Initialize(callback);
        arm_uc_error_t status2 = ARM_UC_PAL_BlockDevice_Initialize(callback);

        if ((status1.error == ERR_NONE) && (status2.error == ERR_NONE)) {
            result.code = ERR_NONE;
        } else {
            result.code = ERR_NOT_READY;
        }
    }

    return result;
}

ARM_UC_PAAL_UPDATE_CAPABILITIES ARM_UCP_FashIAP_BlockDevice_GetCapabilities(void)
{
    ARM_UC_PAAL_UPDATE_CAPABILITIES result = {
        .installer_arm_hash = 0,
        .installer_oem_hash = 0,
        .installer_layout   = 0,
        .firmware_hash      = 1,
        .firmware_hmac      = 0,
        .firmware_campaign  = 0,
        .firmware_version   = 1,
        .firmware_size      = 1
    };

    return result;
}

const ARM_UC_PAAL_UPDATE ARM_UCP_FLASHIAP_BLOCKDEVICE = {
    .Initialize                 = ARM_UCP_FashIAP_BlockDevice_Initialize,
    .GetCapabilities            = ARM_UCP_FashIAP_BlockDevice_GetCapabilities,
    .GetMaxID                   = ARM_UC_PAL_BlockDevice_GetMaxID,
    .Prepare                    = ARM_UC_PAL_BlockDevice_Prepare,
    .Write                      = ARM_UC_PAL_BlockDevice_Write,
    .Finalize                   = ARM_UC_PAL_BlockDevice_Finalize,
    .Read                       = ARM_UC_PAL_BlockDevice_Read,
    .Activate                   = ARM_UC_PAL_BlockDevice_Activate,
    .GetActiveFirmwareDetails   = ARM_UC_PAL_FlashIAP_GetActiveDetails,
    .GetFirmwareDetails         = ARM_UC_PAL_BlockDevice_GetFirmwareDetails,
    .GetInstallerDetails        = ARM_UC_PAL_FlashIAP_GetInstallerDetails
};

#endif // #if defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE)
