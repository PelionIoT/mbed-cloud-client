//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2017 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#include "arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE) && (ARM_UC_FEATURE_PAL_BLOCKDEVICE == 1)
#if defined(TARGET_LIKE_MBED)

#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice_platform.h"
#include "mbed.h"

extern BlockDevice *arm_uc_blockdevice;

int32_t arm_uc_blockdevice_init(void)
{
    return arm_uc_blockdevice->init();
}

uint32_t arm_uc_blockdevice_get_program_size(void)
{
    return arm_uc_blockdevice->get_program_size();
}

uint32_t arm_uc_blockdevice_get_erase_size(void)
{
    return arm_uc_blockdevice->get_erase_size();
}

int32_t arm_uc_blockdevice_erase(uint64_t address, uint64_t size)
{
    return arm_uc_blockdevice->erase(address, size);
}

int32_t arm_uc_blockdevice_program(const uint8_t *buffer,
                                   uint64_t address,
                                   uint32_t size)
{
    return arm_uc_blockdevice->program(buffer, address, size);
}

int32_t arm_uc_blockdevice_read(uint8_t *buffer,
                                uint64_t address,
                                uint32_t size)
{
    return arm_uc_blockdevice->read(buffer, address, size);
}

#endif /* #if defined(TARGET_LIKE_MBED) */
#endif /* defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE) */
