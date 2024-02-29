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

#ifndef ARENAL_IOT_IOT_MQTT_H
#define ARENAL_IOT_IOT_MQTT_H


#include <stdint.h>
#include <stdbool.h>
#include "stdio.h"
#include "iot_log.h"
#include "iot_http.h"

#define TAG_IOT_MQTT  "iot_mqtt"

typedef enum {
    /**
     * @brief 当MQTT实例第一次连接网络成功时, 触发此事件
     */
    IOT_MQTTEVT_CONNECT,
    /**
     * 连接失败
     */
    IOT_MQTTEVT_CONNECT_ERROR,

    /**
     * @brief 当MQTT实例断开网络连接后重连成功时, 触发此事件
     */
    IOT_MQTTEVT_RECONNECT,
    /**
     * @brief 当MQTT实例断开网络连接时, 触发此事件
     */
    IOT_MQTTEVT_DISCONNECT,


} iot_mqtt_event_type_t;

typedef struct iot_mqtt_event_data {
    int error_code;
    int return_code;
} iot_mqtt_event_data_t;




typedef enum {
    /**
     * 一机一密，需要提供ProductKey、DeviceName、DeviceSecret
     */
    IOT_AUTH_DEVICE_SECRET = -1,
    /**
     * 一型一密预注册，需要提供ProductKey、ProductSecret、DeviceName
     */
    IOT_AUTH_DYNAMIC_PRE_REGISTERED = 0,
    /**
     * 一型一密免预注册，需要提供ProductKey、ProductSecret、Name
     */
    IOT_AUTH_DYNAMIC_NO_PRE_REGISTERED = 1
} iot_mqtt_auth_type_t;

typedef struct {
    uint8_t qos;
    uint8_t *topic;
    uint16_t topic_len;
    uint8_t *payload;
    uint32_t payload_len;
} iot_mqtt_pub_data_t;

typedef struct {
    int32_t CodeN;
    char *Code;
    char *Message;
} iot_http_response_meta_data_error_t;


typedef struct {
    char *action;
    char *version;
    iot_http_response_meta_data_error_t responseMetaDataError;
} iot_http_response_meta_data_t;


typedef struct {
    int32_t len;
    char *payload;
} iot_http_response_dynamic_register_result_t;


typedef struct {
    iot_http_response_dynamic_register_result_t result;
    iot_http_response_meta_data_t meta_info;
} iot_http_response_dynamic_register_t;


typedef void(iot_mqtt_topic_handler_fn)(void *mqtt_ctx, iot_mqtt_pub_data_t *pub_data, void *userdata);

typedef void(iot_mqtt_event_callback_fn)(void *mqtt_ctx, iot_mqtt_event_type_t event, iot_mqtt_event_data_t data, void *userdata);

typedef struct iot_mqtt_ctx iot_mqtt_ctx_t;

iot_mqtt_ctx_t *iot_mqtt_init();

void iot_mqtt_clean(iot_mqtt_ctx_t *mqtt_ctx);

void iot_mqtt_set_instance_id(iot_mqtt_ctx_t *mqtt_ctx, char *instance_id);

void iot_mqtt_set_http_host(iot_mqtt_ctx_t *mqtt_ctx, char *http_host);

void iot_mqtt_set_host(iot_mqtt_ctx_t *mqtt_ctx, char *host);

void iot_mqtt_set_port(iot_mqtt_ctx_t *mqtt_ctx, int32_t port);

void iot_mqtt_set_is_tls(iot_mqtt_ctx_t *mqtt_ctx, bool isTls);

void iot_mqtt_set_product_key(iot_mqtt_ctx_t *mqtt_ctx, char *product_key);

void iot_mqtt_set_product_secret(iot_mqtt_ctx_t *mqtt_ctx, char *product_secret);

void iot_mqtt_set_device_name(iot_mqtt_ctx_t *mqtt_ctx, char *device_name);

void iot_mqtt_set_device_secret(iot_mqtt_ctx_t *mqtt_ctx, char *device_secret);

void iot_mqtt_set_auth_type(iot_mqtt_ctx_t *mqtt_ctx, iot_mqtt_auth_type_t auth_type);

void iot_mqtt_add_global_receiver_topic_handler_fn(iot_mqtt_ctx_t *mqtt_ctx, iot_mqtt_topic_handler_fn *fun, void *user_data);

void iot_mqtt_set_event_handler_fn(iot_mqtt_ctx_t *mqtt_ctx, iot_mqtt_event_callback_fn *fun, void *user_data);

/**
 * 连接建立超时时间 不设置的话 默认3000 ms
 * @param mqtt_ctx
 * @param connect_timeout_ms
 */
void iot_mqtt_set_connect_timeout_ms(iot_mqtt_ctx_t *mqtt_ctx, uint32_t connect_timeout_ms);

/**
 * 设置心跳间隔, 默认15s
 * @param mqtt_ctx
 * @param keep_alive_time_secs
 */
void iot_mqtt_set_keep_alive_time_secs(iot_mqtt_ctx_t *mqtt_ctx, uint16_t keep_alive_time_secs);

/**
 * 设置 ping 的超市时间 默认 3000ms
 * @param mqtt_ctx
 * @param time_out
 */
void iot_mqtt_set_ping_timeout_ms(iot_mqtt_ctx_t *mqtt_ctx, uint32_t time_out);

/**
 * 建联时 是否  clean_session
 * @param mqtt_ctx
 * @param clean_session
 */
void iot_mqtt_set_clean_session(iot_mqtt_ctx_t *mqtt_ctx, bool clean_session);


int32_t iot_connect(iot_mqtt_ctx_t *mqtt_ctx);



// 断开链接
int32_t iot_mqtt_disconnect(iot_mqtt_ctx_t *mqtt_ctx);

struct iot_mqtt_dynamic_register_basic_param {
    const char *instance_id;
    const char *product_key;
    const char *device_name;
    int32_t random_num;
    uint64_t timestamp;
    iot_mqtt_auth_type_t auth_type;
};


#endif //ARENAL_IOT_IOT_MQTT_H
