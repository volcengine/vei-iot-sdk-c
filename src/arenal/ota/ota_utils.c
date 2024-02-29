/*
 * Copyright 2022-2024 Beijing Volcano Engine Technology Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ota_utils.h"

static const char *s_ota_upgrade_device_status[UpgradeDeviceStatusCount] = {"ToUpgrade",
                                                                            "Downloading",
                                                                            "Downloaded",
                                                                            "DiffRecovering",
                                                                            "DiffRecovered",
                                                                            "Installing",
                                                                            "Installed",
                                                                            "Success",
                                                                            "Failed"};


const char *iot_ota_job_status_enum_to_string(enum ota_upgrade_device_status_enum status) {
    return s_ota_upgrade_device_status[status];
}

enum ota_upgrade_device_status_enum iot_ota_job_status_str_to_status_enum(struct aws_string *status_str) {
    if (aws_string_eq_c_str(status_str, s_ota_upgrade_device_status[UpgradeDeviceStatusDownloading])) {
        return UpgradeDeviceStatusDownloading;
    } else if (aws_string_eq_c_str(status_str, s_ota_upgrade_device_status[UpgradeDeviceStatusDownloaded])) {
        return UpgradeDeviceStatusDownloaded;
    } else if (aws_string_eq_c_str(status_str, s_ota_upgrade_device_status[UpgradeDeviceStatusInstalling])) {
        return UpgradeDeviceStatusInstalling;
    } else if (aws_string_eq_c_str(status_str, s_ota_upgrade_device_status[UpgradeDeviceStatusInstalled])) {
        return UpgradeDeviceStatusInstalled;
    } else if (aws_string_eq_c_str(status_str, s_ota_upgrade_device_status[UpgradeDeviceStatusSuccess])) {
        return UpgradeDeviceStatusSuccess;
    } else if (aws_string_eq_c_str(status_str, s_ota_upgrade_device_status[UpgradeDeviceStatusDiffRecovering])) {
        return UpgradeDeviceStatusDiffRecovering;
    } else if (aws_string_eq_c_str(status_str, s_ota_upgrade_device_status[UpgradeDeviceStatusDiffRecovered])) {
        return UpgradeDeviceStatusDiffRecovered;
    } else if (aws_string_eq_c_str(status_str, s_ota_upgrade_device_status[UpgradeDeviceStatusFailed])) {
        return UpgradeDeviceStatusFailed;
    } else {
        return UpgradeDeviceStatusFailed;
    }
}


