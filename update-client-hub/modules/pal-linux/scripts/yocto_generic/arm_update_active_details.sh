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

# Note - exit codes 1-20 come from arm_udpate_common.sh.

# Parse command line
#
# HEADER
# FIRMWARE
# LOCATION
# OFFSET
# SIZE
#
. /opt/arm/arm_update_cmdline.sh
. /opt/arm/arm_update_common.sh

if [ -n "$ARM_UPDATE_ACTIVE_DETAILS_LOG_PATH" ]; then
    # Redirect stdout and stderr to the log file
    exec >"$ARM_UPDATE_ACTIVE_DETAILS_LOG_PATH" 2>&1
fi

# header directory
HEADER_DIR=$(dirname "${HEADER}")

# header name (not prefix)
HEADER_NAME="header"

# location where the update client will find the header
HEADER_PATH="${HEADER_DIR}/${HEADER_NAME}.bin"

set -x

# Detect root partitions
root1=$(get_device_for_label rootfs1)
exit_on_error "$?"

root2=$(get_device_for_label rootfs2)
exit_on_error "$?"

# Flag partition
FLAGS=$(get_device_for_label bootflags)
exit_on_error "$?"

# Find the partition that is currently mounted to /
activePartition=$(get_active_root_device)

if [ "$activePartition" = "$root1" ]; then
    activePartitionLabel=rootfs1
elif [ "$activePartition" = "$root2" ]; then
    activePartitionLabel=rootfs2
else
    echo "Current root partition does not have a \"rootfs1\" or \"rootfs2\" label"
    exit 21
fi

ensure_mounted_or_die "$FLAGS" /mnt/flags "$FLAGSFS_TYPE"

# Boot Flags
if [ -e "/mnt/flags/${activePartitionLabel}_header" ]; then
    if ! cp "/mnt/flags/${activePartitionLabel}_header" "$HEADER_PATH"; then
        echo "Failed to copy image header"
        exit 22
    fi
else
    echo "Warning: No active firmware header found!"
    exit 23
fi

exit 0
