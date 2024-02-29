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

#ifndef ARENAL_IOT_LOG_REPORT_H
#define ARENAL_IOT_LOG_REPORT_H

#include "core/iot_core.h"
#include "core/iot_mqtt.h"

typedef struct log_handler log_handler_t;

log_handler_t *aiot_log_init(void);

void aiot_log_set_mqtt_handler(log_handler_t *handle, iot_mqtt_ctx_t *mqtt_handle);

void aiot_log_set_report_switch(log_handler_t *handle, bool is_upload_log, enum aiot_log_level lowest_level);




#endif //ARENAL_IOT_LOG_REPORT_H
