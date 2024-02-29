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

#ifndef ARENAL_IOT_DEVICE_DELAY_H
#define ARENAL_IOT_DEVICE_DELAY_H

#include "core/iot_core.h"
#include <aws/mqtt/mqtt.h>
#include <aws/mqtt/client.h>

/**
 * 订阅 设备延迟弹窗 topic
 * @param tm_handler
 */
void _sub_device_delay_info(void *handler);

/**
 * 接收处理 设备延迟弹窗的方法
 * @param connection
 * @param topic
 * @param payload
 * @param dup
 * @param qos
 * @param retain
 * @param userdata
 */
void _tm_recv_device_delay_info(struct aws_mqtt_client_connection *connection,
                                const struct aws_byte_cursor *topic,
                                const struct aws_byte_cursor *payload,
                                bool dup,
                                enum aws_mqtt_qos qos,
                                bool retain,
                                void *userdata);

/**
 * 发送设备延迟的回复
 * @param handler
 * @param uuid_cur
 * @return
 */
int32_t _tm_send_device_delay_reply_data(void *handler, struct aws_byte_cursor *uuid_cur);

#endif //ARENAL_IOT_DEVICE_DELAY_H
