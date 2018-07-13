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

# Parse kernel command line to find:
#
# Active no.:   ${ACTIVE_SLOT}
# Active slot:  ${ACTIVE_SLOT_MTD}
# Active flags: ${ACTIVE_FLAGS_MTD}
#
# Update no.:   ${UPDATE_SLOT}
# Update slot:  ${UPDATE_SLOT_MTD}
# Update flags: ${UPDATE_FLAGS_MTD}
#

# /proc/cmdline parameter that holds the active slot name
KERNEL_PREFIX="ubi.mtd"

# firmware prefix
FIRMWARE_PREFIX="ROOT_"

# flags prefix
FLAGS_PREFIX="FLAGS_"

#
# parse /proc/cmdline and read the active slot
#

# get parameter
for x in $(cat /proc/cmdline); do
    case "$x" in
        $KERNEL_PREFIX=*)
        LINUX="${x#*=}"
        ;;
    esac
done

# read active slot number
ACTIVE_SLOT=$(echo "${LINUX}" | sed -e "s/${FIRMWARE_PREFIX}//")

# deduce alternate, update slot
if [ "$ACTIVE_SLOT" -eq 0 ]; then
    UPDATE_SLOT=1
else
    UPDATE_SLOT=0
fi

#
# get active mtd for slot and flags
#
ACTIVE_NAME_MTD="${FIRMWARE_PREFIX}${ACTIVE_SLOT}"
ACTIVE_LINE_MTD=$(cat /proc/mtd | grep "${ACTIVE_NAME_MTD}")
ACTIVE_SLOT_MTD=${ACTIVE_LINE_MTD%:*}

ACTIVE_NAME_MTD="${FLAGS_PREFIX}${ACTIVE_SLOT}"
ACTIVE_LINE_MTD=$(cat /proc/mtd | grep "${ACTIVE_NAME_MTD}")
ACTIVE_FLAGS_MTD=${ACTIVE_LINE_MTD%:*}

#
# get update mtd for slot and flags
#
UPDATE_NAME_MTD="${FIRMWARE_PREFIX}${UPDATE_SLOT}"
UPDATE_LINE_MTD=$(cat /proc/mtd | grep ${UPDATE_NAME_MTD})
UPDATE_SLOT_MTD=${UPDATE_LINE_MTD%:*}

UPDATE_NAME_MTD="${FLAGS_PREFIX}${UPDATE_SLOT}"
UPDATE_LINE_MTD=$(cat /proc/mtd | grep ${UPDATE_NAME_MTD})
UPDATE_FLAGS_MTD=${UPDATE_LINE_MTD%:*}

#
# result
#
# echo "Active no.:   ${ACTIVE_SLOT}"
# echo "Active slot:  ${ACTIVE_SLOT_MTD}"
# echo "Active flags: ${ACTIVE_FLAGS_MTD}"
#
# echo "Update no.:   ${UPDATE_SLOT}"
# echo "Update slot:  ${UPDATE_SLOT_MTD}"
# echo "Update flags: ${UPDATE_FLAGS_MTD}"
#
