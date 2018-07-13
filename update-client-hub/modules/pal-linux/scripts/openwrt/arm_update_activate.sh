#!/bin/sh
# ----------------------------------------------------------------------------
# Copyright 2016-2017 ARM Ltd.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

# This script takes two parameters: -f|--firmware and -h|--header
# Parameters are parsed by arm_update_cmdline.sh
#
# It uses arm_update_kernel.sh to parse the the kernel commandline passed to
# the kernel by U-Boot. This command line contains two parameters:
# mbed.root : identifier for the active partition
# mbed.boot : boot loader identifier
#
# If both the firmware and header exists, the script will overwrite the update
# partition with the firmware and write the header to the update flags partition.
# If both operations are successful, the active flags partition is erased.
#
# Boot order:
# <slot 0><slot 1> : boot
# empty - empty : slot 0
# empty - valid : slot 1
# valid - valid : slot 0
# valid - empty : slot 0

# Find mtd partitions
#
# ACTIVE_SLOT
# ACTIVE_SLOT_MTD
# ACTIVE_FLAGS_MTD
# UPDATE_SLOT
# UPDATE_SLOT_MTD
# UPDATE_FLAGS_MTD
#
. arm_update_kernel.sh

# Parse command line
#
# HEADER
# FIRMWARE
# LOCATION
# OFFSET
# SIZE
#
. arm_update_cmdline.sh

#
# Check that header and firmware are set and exist
#
if [ ! -f $HEADER ] || [ -z $HEADER ]; then
    echo "header doesn't exists";
    exit 1;
fi

if [ ! -f $FIRMWARE ] || [ -z $FIRMWARE ]; then
    echo "firmware doesn't exists"
    exit 1;
fi

# write firmware to ubi partition
ubiformat "/dev/${UPDATE_SLOT_MTD}" -f $FIRMWARE --yes
VALUE=$?

# exit if return code is not zero
if [ $VALUE -ne 0 ]; then
    echo "failed to format new image"
    exit $VALUE
fi

# Check if mtd-utils-flash-erase and mtd-utils-nandwrite are installed
if ! which "nandwrite" &>/dev/null || ! which "flash_erase" &>/dev/null; then
    echo "Either nandwrite or flash_erase tools are missing"
    exit 1
fi

# erase sector
flash_erase "/dev/${UPDATE_FLAGS_MTD}" 0 1
VALUE=$?

# exit if return code is not zero
if [ $VALUE -ne 0 ]; then
    echo "failed to erase update flags"
    exit $VALUE
fi

# write header to update partition
# if this is the default partition, this will activate it
nandwrite -p -s 0 "/dev/${UPDATE_FLAGS_MTD}" $HEADER
VALUE=$?

# exit if return code is not zero
if [ $VALUE -ne 0 ]; then
    echo "failed to write new header"
    exit $VALUE
fi

# erase active header
# if this is the default partition, this will activate the update partition
flash_erase "/dev/${ACTIVE_FLAGS_MTD}" 0 1
VALUE=$?

# exit if return code is not zero
if [ $VALUE -ne 0 ]; then
    echo "failed to erase active header"
    exit $VALUE
fi

exit 0
