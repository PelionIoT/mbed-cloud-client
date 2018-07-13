#!/bin/sh
# ----------------------------------------------------------------------------
# Copyright 2017 ARM Ltd.
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

# Note - this library file uses return and exit codes 1-20 to indicate errors.
#

LOCAL_CONFIG_PATH=/opt/arm/arm_update_local_config.sh
ROOTFS_TYPE="ext4"
FLAGSFS_TYPE="ext4"

# Given an exit status, exits with that status if it is non-zero, otherwise
# does nothing
#
# $1: exit status to check
exit_on_error() {
eoeStatus="$1"
    if [ "$eoeStatus" -ne 0 ]; then
        exit "$eoeStatus"
    fi
}

# Get the path to the device file for the partition with the given label.⏎
#
# $1: the partition label
get_device_for_label() {
gdflLabel="$1"

    gdflDev=$(readlink -f "/dev/disk/by-label/${gdflLabel}")
    if [ "$?" -ne 0 ]; then
        echo "Failed to find device file for partition with label \"${gdflLabel}\""
        return 1;
    fi
    if [ ! -b "$gdflDev" ]; then
        echo "Device with label \"${gdflLabel}\" is not a block device"
        return 2;
    fi
    printf "%s" "$gdflDev"
}

# Get the mountpoint for a device.
# If the device is not mounted then a mountpoint is not printed but the
# function still returns successfully.
#
# $1: path to the device file
get_mountpoint() {
gmDevice="$1"
    lsblk -nro MOUNTPOINT "$gmDevice"
    if [ "$?" -ne 0 ]; then
        echo "Unable to determine mountpoint (if any) of device \"${gmDevice}\""
        return 3
    fi
}

# Do whatever is required so that the given device is not mounted.
# Errors cause an exit.
#
# $1: path to device to unmount (if mounted).
ensure_not_mounted_or_die() {
enmodDevice="$1"

    enmodMountpoint=$(get_mountpoint "$enmodDevice")
    exit_on_error "$?"

    if [ "$enmodMountpoint" = "" ]; then
        return 4
    fi

    if ! umount "$enmodDevice"; then
        echo "Unable to unmount device \"${enmodDevice}\""
        exit 5
    fi
}

# Do whatever is required so that the given device is mounted at the given
# mountpoint, including creating the mountpoint if necessary.
# Errors cause an exit.
#
# $1: path to the device to mount
# $2: the mountpoint for the device
ensure_mounted_or_die() {
emodDevice="$1"
emodMountpoint="$2"
emodFsType="$3"

    emodCurrMountpoint=$(get_mountpoint "$emodDevice")
    exit_on_error "$?"

    case  "$emodCurrMountpoint" in
        "$emodMountpoint")
            return 6
            ;;
        "")
            ;;
        *)
            if ! umount "$emodDevice"; then
                echo "Unable to unmount device \"${emodDevice}\""
                exit 7
            fi
            ;;
    esac

    if ! mkdir -p "$emodMountpoint"; then
        echo "Unable to create mountpoint \"${emodMountpoint}\""
        exit 8
    fi

    if ! mount -t "$emodFsType" "$emodDevice" "$emodMountpoint"; then
        echo "Unable to mount device \"${emodDevice}\" at \"${emodMountpoint}\""
        exit 9
    fi
}

# Find the device that is currently mounted to /
get_active_root_device() {
    lsblk -nrpo NAME,MOUNTPOINT | grep -e ".* /$" | cut -d ' ' -f1
}

[ -e "$LOCAL_CONFIG_PATH" ] && . "$LOCAL_CONFIG_PATH"
