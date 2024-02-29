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

#include "service.h"
#include <core/iot_util.h>
#include <core/iot_log.h>
#include <core/iot_core_header.h>
#include <aws/common/json.h>
#include "event.h"
#include "iot_tm_api.h"
#include "thing_model/iot_tm_header.h"


void iot_tm_msg_service_call_reply_init(iot_tm_msg_service_call_reply_t **reply,
                                             const char *module_key,
                                             const char *identifier,
                                             const char *topic_uuid,
                                             const char *msgId,
                                             int32_t code
) {
    iot_tm_msg_service_call_reply_t *reply_data = aws_mem_calloc(get_iot_core_context()->alloc, 1, sizeof(iot_tm_msg_service_call_reply_t));
    reply_data->id = msgId;
    reply_data->version = SDK_VERSION;
    reply_data->module_key = module_key;
    reply_data->identifier = identifier;
    reply_data->topic_uuid = topic_uuid;
    reply_data->code = code;
    reply_data->params = (void*) aws_json_value_new_object(get_iot_core_context()->alloc);
    *reply = reply_data;
}

void iot_tm_msg_service_call_reply_set_prams_json_str(iot_tm_msg_service_call_reply_t *reply, const char* param_json_str) {
    if (reply->params != NULL) {
        aws_json_value_destroy((struct aws_json_value*) reply->params);
    }
    reply->params = (void*) aws_json_value_new_from_string(get_iot_core_context()->alloc, aws_byte_cursor_from_c_str(param_json_str));
}

void iot_tm_msg_service_call_reply_free(iot_tm_msg_service_call_reply_t* reply) {
//    aws_mem_release(get_iot_core_context()->alloc, reply->id);
//    aws_mem_release(get_iot_core_context()->alloc, reply->module_key);
//    aws_mem_release(get_iot_core_context()->alloc, reply->identifier);
    if (reply->payload_root == NULL) {
        aws_json_value_destroy(reply->payload_root);
    } else if (reply->params != NULL) {
        aws_json_value_destroy(reply->params);
    }
    aws_mem_release(get_iot_core_context()->alloc, reply);
}

void* iot_tm_msg_service_call_reply_payload(iot_tm_msg_service_call_reply_t* reply) {
    if (reply->payload_root == NULL) {
        reply->payload_root = aws_json_value_new_object(get_iot_core_context()->alloc);
        aws_json_add_str_val((struct aws_thread_once*) reply->payload_root, "id", reply->id);
        aws_json_add_num_val((struct aws_thread_once*) reply->payload_root, "code", reply->code);
        aws_json_add_json_obj((struct aws_thread_once*) reply->payload_root, "Data", reply->params);
    }
    return reply->payload_root;
}


int32_t _tm_send_service_call_reply(void *handler, const char *topic, const void *msg_p) {
    // 发送数据给服务端
    tm_handle_t *dm_handle = (tm_handle_t *) handler;
    iot_tm_msg_t *msg = (iot_tm_msg_t *) msg_p;

    int ret = CODE_SUCCESS;
    struct aws_byte_buf payload_buf = aws_json_obj_to_bye_buf(dm_handle->allocator, ((struct aws_json_value*)iot_tm_msg_service_call_reply_payload(msg->data.service_call_reply)));
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&payload_buf);
    struct aws_byte_cursor public_topic = aws_byte_cursor_from_c_str(topic);
    uint16_t packet_id = aws_mqtt_client_connection_publish(dm_handle->mqtt_handle->mqtt_connection, &public_topic,
                                                            AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                                            _tm_mqtt_post_on_complete_fn,
                                                            NULL);
    LOGD(TAG_IOT_MQTT, "_tm_send_service_cal_reply_data call packet_id = %d, topic = %.*s, payload = %.*s", packet_id, AWS_BYTE_CURSOR_PRI(public_topic),
         AWS_BYTE_CURSOR_PRI(payload_cur));

    // 回收内存数据
    aws_byte_buf_clean_up(&payload_buf);
    if (packet_id == 0) {
        ret = STATE_DM_MQTT_PUBLISH_ERROR;
    }
    return ret;

}

void __tm_send_server_service_call_reply(void* handler, const char* module_key, const char* identifier,
                                         const char* topic_uuid,const char* msg_id, int32_t code) {
    tm_handle_t *dm_handle = (tm_handle_t *) handler;

    iot_tm_msg_t service_reply_msg = {0};
    service_reply_msg.type = IOT_TM_MSG_SERVICE_CALL_REPLY;
    iot_tm_msg_service_call_reply_t *reply;
    iot_tm_msg_service_call_reply_init(&reply, module_key, identifier, topic_uuid,msg_id, code);
    service_reply_msg.data.service_call_reply = reply;
    iot_tm_send(dm_handle, &service_reply_msg);
    iot_tm_msg_service_call_reply_free(reply);

}

void _tm_recv_service_call(struct aws_mqtt_client_connection *connection,
                           const struct aws_byte_cursor *topic,
                           const struct aws_byte_cursor *payload,
                           bool dup,
                           enum aws_mqtt_qos qos,
                           bool retain,
                           void *userdata) {


    //  payload = {"ID":"638c44034a621d7833731ae3","Version":"1.0.0","Params":{"test_num_in":11}}
    LOGD(TAG_IOT_MQTT, "_tm_recv_service_call call topic = %.*s,  payload = %.*s", AWS_BYTE_CURSOR_PRI(*topic), AWS_BYTE_CURSOR_PRI(*payload));
    tm_handle_t *dm_handle = (tm_handle_t *) userdata;
    if (NULL == dm_handle->recv_handler) {
        return;
    }

    iot_tm_recv_t recv = {0};
    recv.type = IOT_TM_RECV_SERVICE_CALL;

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

    struct aws_byte_cursor module_key_cur = {0};
    aws_array_list_get_at(&topic_split_data_list, &module_key_cur, 5);

    struct aws_byte_cursor identifier_cur = {0};
    aws_array_list_get_at(&topic_split_data_list, &identifier_cur, 6);

    struct aws_byte_cursor topic_uuid_cur = {0};
    aws_array_list_get_at(&topic_split_data_list, &topic_uuid_cur, 8);


    // 数据封装
    iot_tm_recv_service_call_t service_call = {0};
    struct aws_json_value *payload_json = aws_json_value_new_from_string(dm_handle->allocator, *payload);
    service_call.msg_id = aws_json_get_str(dm_handle->allocator, payload_json, "ID");
    service_call.version = aws_json_get_str(dm_handle->allocator, payload_json, "Version");
    service_call.module_key = aws_cur_to_char_str(dm_handle->allocator, &module_key_cur);
    service_call.identifier = aws_cur_to_char_str(dm_handle->allocator, &identifier_cur);
    service_call.topic_uuid = aws_cur_to_char_str(dm_handle->allocator, &topic_uuid_cur);
    struct aws_byte_buf param_buf = aws_json_get_json_obj_to_bye_buf(dm_handle->allocator, payload_json, "Params");
    service_call.params_json_str = aws_buf_to_char_str(dm_handle->allocator, &param_buf);
    aws_byte_buf_clean_up(&param_buf);
    recv.data.service_call = service_call;

    // 回调给业务
    dm_handle->recv_handler(dm_handle, &recv, dm_handle->userdata);

    // reply server
    __tm_send_server_service_call_reply(dm_handle, service_call.module_key, service_call.identifier, service_call.topic_uuid, service_call.msg_id, 0);

    // 回收内存
    aws_mem_release(dm_handle->allocator, service_call.msg_id);
    aws_mem_release(dm_handle->allocator, service_call.module_key);
    aws_mem_release(dm_handle->allocator, service_call.identifier);
    aws_mem_release(dm_handle->allocator, service_call.params_json_str);
    aws_mem_release(dm_handle->allocator, service_call.version);
    aws_mem_release(dm_handle->allocator, service_call.topic_uuid);
    aws_mem_release(dm_handle->allocator, recv.product_key);
    aws_mem_release(dm_handle->allocator, recv.device_name);
    aws_json_value_destroy(payload_json);
    aws_array_list_clean_up(&topic_split_data_list);


}