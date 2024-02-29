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

#ifndef ARENAL_IOT_OTA_UTILS_H
#define ARENAL_IOT_OTA_UTILS_H

#include "aws/common/string.h"

enum ota_upgrade_device_status_enum {
    UpgradeDeviceStatusToUpgrade,
    UpgradeDeviceStatusDownloading,
    UpgradeDeviceStatusDownloaded,
    UpgradeDeviceStatusDiffRecovering,
    UpgradeDeviceStatusDiffRecovered,
    UpgradeDeviceStatusInstalling,
    UpgradeDeviceStatusInstalled,
    UpgradeDeviceStatusSuccess,
    UpgradeDeviceStatusFailed,
    UpgradeDeviceStatusCount,
};


struct aws_string *aes_decode(struct aws_allocator *allocator, const char *device_secret, const char *encrypt_data) ;
const char *iot_ota_job_status_enum_to_string(enum ota_upgrade_device_status_enum status);

enum ota_upgrade_device_status_enum iot_ota_job_status_str_to_status_enum(struct aws_string *status_str);

#endif //ARENAL_IOT_OTA_UTILS_H
