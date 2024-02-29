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

#include "custom_topic.h"
#include <core/iot_util.h>
#include <core/iot_log.h>
#include <core/iot_core_header.h>
#include <aws/common/json.h>
#include "iot_tm_api.h"
#include "iot_tm_header.h"

void iot_tm_msg_aiot_tm_msg_custom_topic_post_init(iot_tm_msg_custom_topic_post_t **custom_topic_post, char *custom_topic_suffix, char *payload_json) {
    iot_tm_msg_custom_topic_post_t *data = aws_mem_calloc(get_iot_core_context()->alloc, 1, sizeof(iot_tm_msg_custom_topic_post_t));
    data->custom_topic_suffix = custom_topic_suffix;
    data->params = payload_json;

    *custom_topic_post = data;
}

void iot_tm_msg_aiot_tm_msg_custom_topic_post_free(iot_tm_msg_custom_topic_post_t *custom_topic_post) {
    aws_mem_release(get_iot_core_context()->alloc, custom_topic_post);
}

char* iot_tm_msg_aiot_tm_msg_custom_topic_post_payload(iot_tm_msg_custom_topic_post_t *custom_topic_post) {
    return custom_topic_post->params;
}

int32_t _tm_send_custom_topic_post_data(void *handler, const char *topic, const void *msg_p) {
    tm_handle_t *dm_handle = (tm_handle_t *) handler;
    iot_tm_msg_t *msg = (iot_tm_msg_t *) msg_p;

    int ret = CODE_SUCCESS;
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_c_str(iot_tm_msg_aiot_tm_msg_custom_topic_post_payload(msg->data.custom_topic_post));
    struct aws_byte_cursor public_topic = aws_byte_cursor_from_c_str(topic);
    uint16_t packet_id = aws_mqtt_client_connection_publish(dm_handle->mqtt_handle->mqtt_connection, &public_topic,
                                                            AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                                            _tm_mqtt_post_on_complete_fn,
                                                            NULL);
    LOGD(TAG_IOT_MQTT, "_tm_send_custom_topic_post_data call packet_id = %d, topic = %.*s, payload = %.*s", packet_id, AWS_BYTE_CURSOR_PRI(public_topic),
         AWS_BYTE_CURSOR_PRI(payload_cur));

    if (packet_id == 0) {
        ret = STATE_DM_MQTT_PUBLISH_ERROR;
    }
    return ret;
}


int32_t tm_sub_custom_topic(void *handler, const char *topic_suffix) {
    // 订阅 topic
    tm_handle_t *dm_handle = (tm_handle_t *) handler;
    struct aws_string *topic_suffix_string = aws_string_new_from_c_str(dm_handle->allocator, topic_suffix);
    char *topic = iot_get_topic_with_1_param(dm_handle->allocator, "sys/%s/%s/custom/%s", dm_handle->mqtt_handle->product_key, dm_handle->mqtt_handle->device_name,
                                             topic_suffix_string);
    iot_mqtt_sub(dm_handle->mqtt_handle, topic, 1, _tm_recv_custom_topic, handler);
    aws_mem_release(dm_handle->allocator, topic);
}

void _tm_recv_custom_topic(struct aws_mqtt_client_connection *connection,
                           const struct aws_byte_cursor *topic,
                           const struct aws_byte_cursor *payload,
                           bool dup,
                           enum aws_mqtt_qos qos,
                           bool retain,
                           void *userdata) {
    LOGD(TAG_IOT_MQTT, "_tm_recv_custom_topic call topic = %.*s,  payload = %.*s", AWS_BYTE_CURSOR_PRI(*topic), AWS_BYTE_CURSOR_PRI(*payload));
    tm_handle_t *dm_handle = (tm_handle_t *) userdata;
    if (NULL == dm_handle->recv_handler) {
        return;
    }

    iot_tm_recv_t recv = {0};
    recv.type = IOT_TM_RECV_CUSTOM_TOPIC;

    // 基于 topic 获取 product_key device_name module_key
    struct aws_array_list topic_split_data_list;
    aws_array_list_init_dynamic(&topic_split_data_list, dm_handle->allocator, 8, sizeof(struct aws_byte_cursor));
    aws_byte_cursor_split_on_char(topic, '/', &topic_split_data_list);

    struct aws_byte_cursor product_key_cur = {0};
    aws_array_list_get_at(&topic_split_data_list, &product_key_cur, 1);
    recv.product_key = aws_cur_to_char_str(dm_handle->allocator, &product_key_cur);

    struct aws_byte_cursor device_name_cur = {0};
    aws_array_list_get_at(&topic_split_data_list, &device_name_cur, 2);
    recv.device_name = aws_cur_to_char_str(dm_handle->allocator, &device_name_cur);

    struct aws_byte_cursor custom_topic_cur = {0};
    aws_array_list_get_at(&topic_split_data_list, &custom_topic_cur, 4);

    // 数据封装
    iot_tm_recv_custom_topic_t custom_topic_data = {0};
    custom_topic_data.params_json_str = aws_cur_to_char_str(dm_handle->allocator, payload);
    custom_topic_data.custom_topic_suffix = aws_cur_to_char_str(dm_handle->allocator, &custom_topic_cur);
    recv.data.custom_topic = custom_topic_data;


    // 回调给业务
    dm_handle->recv_handler(dm_handle, &recv, dm_handle->userdata);
    aws_mem_release(dm_handle->allocator, custom_topic_data.params_json_str);
    aws_mem_release(dm_handle->allocator, recv.product_key);
    aws_mem_release(dm_handle->allocator, recv.device_name);
    aws_array_list_clean_up(&topic_split_data_list);


}