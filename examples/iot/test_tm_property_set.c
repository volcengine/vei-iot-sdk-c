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
// 属性下发
//

#define TAG "test_tm_property_set.c"

#include <unistd.h>
#include <core/iot_log.h>
#include <thing_model/iot_tm_api.h>
#include "core/iot_mqtt.h"
#include "thing_model/property.h"
#include "test_params.h"

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
    switch (recv->type) {
        case IOT_TM_RECV_PROPERTY_SET: {
            DEVICE_LOGD(TAG, "test_aiot_dm_recv_handler_t property_set.msg_id = %s service_call.params_json_str = %s", recv->data.property_set.msg_id,
                        recv->data.property_set.params);

            iot_tm_msg_t property_set_post_reply_msg = {0};
            property_set_post_reply_msg.type = IOT_TM_MSG_PROPERTY_SET_REPLY;
            iot_tm_msg_property_set_post_reply_t *reply;
            iot_property_set_post_reply_init(&reply, recv->data.property_set.msg_id, 0);
            property_set_post_reply_msg.data.property_set_post_reply = reply;
            iot_tm_send(dm, &property_set_post_reply_msg);
            iot_property_set_post_reply_free(reply);
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

    sleep(1000);

    ret = iot_mqtt_disconnect(mqtt_ctx);
    if (ret != 0) {
        DEVICE_LOGD(TAG, "iot_disconnect error ret =%d ", ret);
        iot_mqtt_clean(mqtt_ctx);
        return -1;
    }
}
