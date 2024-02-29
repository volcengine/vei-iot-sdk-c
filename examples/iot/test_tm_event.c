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

//
// 事件上报
//

#define TAG "test_tm_event.c"

#include <unistd.h>
#include "thing_model/event.h"
#include "test_params.h"
#include "thing_model/iot_tm_api.h"

char * SAMPLE_HTTP_HOST = "<PROVIDE_CORRECT_VALUE_HERE>";
char * SAMPLE_INSTANCE_ID = "<PROVIDE_CORRECT_VALUE_HERE>";
char * SAMPLE_MQTT_HOST = "<PROVIDE_CORRECT_VALUE_HERE>";
char * SAMPLE_DEVICE_NAME = "<PROVIDE_CORRECT_VALUE_HERE>";
char * SAMPLE_DEVICE_SECRET = "<PROVIDE_CORRECT_VALUE_HERE>";
char * SAMPLE_PRODUCT_KEY = "<PROVIDE_CORRECT_VALUE_HERE>";
char * SAMPLE_PRODUCT_SECRET = "<PROVIDE_CORRECT_VALUE_HERE>";

tm_handle_t *dm;

void s_test_iot_mqtt_topic_handler_fn(void *mqtt_ctx, iot_mqtt_pub_data_t *pub_data, void *userdata) {
    DEVICE_LOGD(TAG, "s_test_iot_mqtt_topic_handler_fn topic =%s payload =%s ", pub_data->topic, pub_data->payload);
}

void s_test_iot_mqtt_event_callback_fn(void *mqtt_ctx, iot_mqtt_event_type_t event, iot_mqtt_event_data_t data, void *userdata) {
    DEVICE_LOGD(TAG, "s_test_iot_mqtt_event_callback_fn event =%d data.error_code = %d data.return_code = %d", event, data.error_code, data.return_code);

    switch (event) {
        case IOT_MQTTEVT_CONNECT: {

        }
        break;
    }
}

void test_aiot_dm_recv_handler_t(void *handler, const iot_tm_recv_t *recv, void *userdata) {
    tm_handle_t *dm_handle = (tm_handle_t *) handler;
    switch (recv->type) {
        case IOT_TM_RECV_EVENT_POST_REPLY: {
            DEVICE_LOGD(TAG, "test_aiot_dm_recv_handler_t property_set id = %s, code = %d module_key = %s, identifier = %s",
                        recv->data.event_post_reply.msg_id,
                        recv->data.event_post_reply.code,
                        recv->data.event_post_reply.module_key,
                        recv->data.event_post_reply.identifier);
        }
        break;
    }
}

int main(void) {
    int ret = 0;

    // 初始化
    iot_core_init();

    // 设置 log 保存地址
    iot_log_init(g_log_dir);

    // mqtt 初始化
    iot_mqtt_ctx_t *mqtt_ctx = iot_mqtt_init();

    // 设置 mqtt 连接配置
    iot_mqtt_set_http_host(mqtt_ctx, SAMPLE_HTTP_HOST);
    iot_mqtt_set_instance_id(mqtt_ctx, SAMPLE_INSTANCE_ID);
    iot_mqtt_set_host(mqtt_ctx, SAMPLE_MQTT_HOST);
    iot_mqtt_set_port(mqtt_ctx, 1883);
    iot_mqtt_set_device_name(mqtt_ctx, SAMPLE_DEVICE_NAME);
    iot_mqtt_set_device_secret(mqtt_ctx, SAMPLE_DEVICE_SECRET);
    iot_mqtt_set_product_key(mqtt_ctx, SAMPLE_PRODUCT_KEY);
    iot_mqtt_set_product_secret(mqtt_ctx, SAMPLE_PRODUCT_SECRET);
    // 设置连接鉴权类型
    iot_mqtt_set_auth_type(mqtt_ctx, IOT_AUTH_DEVICE_SECRET);

    // 设置全局的 topic handler
    iot_mqtt_add_global_receiver_topic_handler_fn(mqtt_ctx, s_test_iot_mqtt_topic_handler_fn, NULL);

    // 设置mqtt 连接事件回调
    iot_mqtt_set_event_handler_fn(mqtt_ctx, s_test_iot_mqtt_event_callback_fn, NULL);

    // 连接 Mqtt 同步
    ret = iot_connect(mqtt_ctx);
    if (ret != 0) {
        DEVICE_LOGD(TAG, "iot_connect error ret =%d ", ret);
        iot_mqtt_clean(mqtt_ctx);
        return -1;
    }

    dm = iot_tm_init();
    iot_tm_set_mqtt_handler(dm, mqtt_ctx);
    iot_tm_set_tm_recv_handler_t(dm, test_aiot_dm_recv_handler_t, dm);

    // 构造发生数据
    iot_tm_msg_t dm_msg_test_event_num = {0};
    dm_msg_test_event_num.type = IOT_TM_MSG_EVENT_POST;

    // 创建 event 数据
    iot_tm_msg_event_post_t *event_test_num_post;
    iot_tm_msg_event_post_init(&event_test_num_post, "test_service", "test_event_a");

    // 添加Num 参数
    iot_tm_msg_event_post_param_add_num(event_test_num_post, "param1", 12);
    dm_msg_test_event_num.data.event_post = event_test_num_post;

    // 发送数据
    ret = iot_tm_send(dm, &dm_msg_test_event_num);
    if (ret != CODE_SUCCESS) {
        DEVICE_LOGD(TAG, "iot_tm_send error ret =%d ", ret);
    }
    // 释放内存
    iot_tm_msg_event_post_free(event_test_num_post);

    sleep(1);

    iot_tm_msg_t dm_msg_test_event_string = {0};
    dm_msg_test_event_string.type = IOT_TM_MSG_EVENT_POST;
    iot_tm_msg_event_post_t *event_test_string_post;
    iot_tm_msg_event_post_init(&event_test_string_post, "skin_event", "skin_event_string");
    // 添加 String 参数
    iot_tm_msg_event_post_param_add_string(event_test_string_post, "skin_string", "test_string hello");
    dm_msg_test_event_string.data.event_post = event_test_string_post;
    ret = iot_tm_send(dm, &dm_msg_test_event_string);
    if (ret != CODE_SUCCESS) {
        DEVICE_LOGD("test_mqtt", "iot_tm_send dm_msg_test_event_string error ret =%d ", ret);
    }
    iot_tm_msg_event_post_free(event_test_string_post);

    sleep(1);

    // 测试直接传递 json string
    iot_tm_msg_t dm_msg_test_event_bool = {0};
    dm_msg_test_event_bool.type = IOT_TM_MSG_EVENT_POST;
    iot_tm_msg_event_post_t *event_test_bool_post;
    iot_tm_msg_event_post_init(&event_test_bool_post, "skin_event", "skin_event_bool");
    // 直接传递 json  string
    iot_tm_msg_event_post_set_prams_json_str(event_test_bool_post, "{\"test_bool\":1}");
    dm_msg_test_event_bool.data.event_post = event_test_bool_post;
    ret = iot_tm_send(dm, &dm_msg_test_event_bool);
    if (ret != CODE_SUCCESS) {
        DEVICE_LOGD("test_mqtt", "iot_tm_send dm_msg_test_event_bool error ret =%d ", ret);
    }
    iot_tm_msg_event_post_free(event_test_bool_post);

    sleep(1000);
}
