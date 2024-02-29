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

#include <core/iot_util.h>
#include <core/iot_log.h>
#include <core/iot_core_header.h>
#include "iot_tm_api.h"
#include "iot_tm_header.h"
#include "device_delay.h"

void _sub_device_delay_info(void *handler) {
    // 订阅 topic
    tm_handle_t *tm_handle = (tm_handle_t *) handler;
    char *topic = iot_get_common_topic(tm_handle->allocator, "sys/%s/%s/delay/+/post", tm_handle->mqtt_handle->product_key, tm_handle->mqtt_handle->device_name);
    iot_mqtt_sub(tm_handle->mqtt_handle, topic, 1, _tm_recv_device_delay_info, handler);
    aws_mem_release(tm_handle->allocator, topic);
}

void _tm_recv_device_delay_info(struct aws_mqtt_client_connection *connection,
                                const struct aws_byte_cursor *topic,
                                const struct aws_byte_cursor *payload,
                                bool dup,
                                enum aws_mqtt_qos qos,
                                bool retain,
                                void *userdata) {

    LOGD(TAG_IOT_MQTT, "_tm_recv_device_delay_info call topic = %.*s,  payload = %.*s", AWS_BYTE_CURSOR_PRI(*topic), AWS_BYTE_CURSOR_PRI(*payload));
    tm_handle_t *dm_handle = (tm_handle_t *) userdata;

    struct aws_array_list topic_split_data_list;
    aws_array_list_init_dynamic(&topic_split_data_list, dm_handle->allocator, 4, sizeof(struct aws_byte_cursor));
    aws_byte_cursor_split_on_char(topic, '/', &topic_split_data_list);

    struct aws_byte_cursor uuid_cur = {0};
    aws_array_list_get_at(&topic_split_data_list, &uuid_cur, 4);
    _tm_send_device_delay_reply_data(dm_handle, &uuid_cur);
    aws_array_list_clean_up(&topic_split_data_list);
}

int32_t _tm_send_device_delay_reply_data(void *handler, struct aws_byte_cursor *uuid_cur) {
    tm_handle_t *dm_handle = (tm_handle_t *) handler;
    int ret = CODE_SUCCESS;

    struct aws_string *uuid_string = aws_string_new_from_cursor(dm_handle->allocator, uuid_cur);
    char *reply_topic = iot_get_topic_with_1_param(dm_handle->allocator, "sys/%s/%s/delay/%s/post_reply",
                                                    dm_handle->mqtt_handle->product_key, dm_handle->mqtt_handle->device_name,
                                                    uuid_string);


    struct aws_byte_cursor public_topic = aws_byte_cursor_from_c_str(reply_topic);
    struct aws_byte_cursor payload_cur = {0};
    uint16_t packet_id = aws_mqtt_client_connection_publish(dm_handle->mqtt_handle->mqtt_connection, &public_topic,
                                                            AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                                            _tm_mqtt_post_on_complete_fn,
                                                            NULL);
    LOGD(TAG_IOT_MQTT, "_tm_send_device_delay_reply_data call packet_id = %d, topic = %.*s, payload = %.*s", packet_id, AWS_BYTE_CURSOR_PRI(public_topic),
         AWS_BYTE_CURSOR_PRI(payload_cur));

    // 回收内存数据
    aws_mem_release(dm_handle->allocator, reply_topic);
    if (packet_id == 0) {
        ret = STATE_DM_MQTT_PUBLISH_ERROR;
    }
    return ret;

}