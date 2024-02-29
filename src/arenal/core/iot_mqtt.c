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

#include <aws/mqtt/mqtt.h>
#include <aws/mqtt/client.h>
#include <aws/cal/hmac.h>
#include <aws/common/encoding.h>
#include <aws/common/json.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/socket.h>
#include <aws/common/date_time.h>
#include <ota/ota_utils.h>
#include "iot_mqtt.h"
#include "iot_ca.h"
#include "iot_util.h"
#include "iot_core.h"
#include "iot_core_header.h"


iot_mqtt_ctx_t *iot_mqtt_init() {
    iot_core_init();

    iot_mqtt_ctx_t *mqtt_ctx = aws_mem_acquire(get_iot_core_context()->alloc, sizeof(iot_mqtt_ctx_t));
    AWS_ZERO_STRUCT(*mqtt_ctx);
    mqtt_ctx->alloc = get_iot_core_context()->alloc;
    aws_mqtt_library_init(mqtt_ctx->alloc);


    mqtt_ctx->connect_timeout_ms = 3000;
    mqtt_ctx->keep_alive_time_secs = 15;
    mqtt_ctx->ping_timeout_ms = 3000;
    mqtt_ctx->clean_session = false;
    aws_mutex_init(&mqtt_ctx->lock);
    aws_condition_variable_init(&mqtt_ctx->cvar);
    // 设置初始状态为-1
    mqtt_ctx->last_event_data.error_code = -1;
    mqtt_ctx->last_event_data.return_code = -1;


    return mqtt_ctx;
    // TODO  设置默认参数  连接超时设置等
}

void iot_mqtt_set_host(iot_mqtt_ctx_t *mqtt_ctx, char *host) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->host = aws_string_new_from_c_str(mqtt_ctx->alloc, host);
}


void iot_mqtt_set_http_host(iot_mqtt_ctx_t *mqtt_ctx, char *http_host) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->http_host = aws_string_new_from_c_str(mqtt_ctx->alloc, http_host);
}


void iot_mqtt_set_instance_id(iot_mqtt_ctx_t *mqtt_ctx, char *instance_id) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->instance_id = aws_string_new_from_c_str(mqtt_ctx->alloc, instance_id);
}

void iot_mqtt_set_port(iot_mqtt_ctx_t *mqtt_ctx, int32_t port) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->port = port;
}

void iot_mqtt_set_is_tls(iot_mqtt_ctx_t *mqtt_ctx, bool isTls) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->isTls = isTls;
}

void iot_mqtt_set_product_key(iot_mqtt_ctx_t *mqtt_ctx, char *product_key) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->product_key = aws_string_new_from_c_str(mqtt_ctx->alloc, product_key);
}

void iot_mqtt_set_product_secret(iot_mqtt_ctx_t *mqtt_ctx, char *product_secret) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->product_secret = aws_string_new_from_c_str(mqtt_ctx->alloc, product_secret);
}

void iot_mqtt_set_device_name(iot_mqtt_ctx_t *mqtt_ctx, char *device_name) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->device_name = aws_string_new_from_c_str(mqtt_ctx->alloc, device_name);
}

void iot_mqtt_set_device_secret(iot_mqtt_ctx_t *mqtt_ctx, char *device_secret) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->device_secret = aws_string_new_from_c_str(mqtt_ctx->alloc, device_secret);
}

void iot_mqtt_set_auth_type(iot_mqtt_ctx_t *mqtt_ctx, iot_mqtt_auth_type_t auth_type) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->auth_type = auth_type;
}

void iot_mqtt_add_global_receiver_topic_handler_fn(iot_mqtt_ctx_t *mqtt_ctx, iot_mqtt_topic_handler_fn *fun, void *user_data) {
    if (mqtt_ctx == NULL) {
        return;
    }
    if (mqtt_ctx->global_topic_handler_fn_list == NULL) {
        mqtt_ctx->global_topic_handler_fn_list = aws_mem_acquire(mqtt_ctx->alloc, sizeof(struct aws_linked_list));
        aws_linked_list_init(mqtt_ctx->global_topic_handler_fn_list);
    }

    iot_mqtt_sub_topic_map_item_t *item = aws_mem_acquire(mqtt_ctx->alloc, sizeof(iot_mqtt_sub_topic_map_item_t));
    AWS_ZERO_STRUCT(*item);
    item->user_data = user_data;
    item->handler_fn = fun;
    aws_linked_list_push_back(mqtt_ctx->global_topic_handler_fn_list, &item->node);
}

void iot_mqtt_set_event_handler_fn(iot_mqtt_ctx_t *mqtt_ctx, iot_mqtt_event_callback_fn *fun, void *user_data) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->default_mqtt_event_callback_fn = fun;
    mqtt_ctx->default_mqtt_event_callback_fn_user_data = user_data;
}


/**
 * 连接建立超时时间 不设置的话 默认3000 ms
 * @param mqtt_ctx
 * @param connect_timeout_ms
 */
void iot_mqtt_set_connect_timeout_ms(iot_mqtt_ctx_t *mqtt_ctx, uint32_t connect_timeout_ms) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->connect_timeout_ms = connect_timeout_ms;
}

/**
 * 设置心跳间隔, 默认15s
 * @param mqtt_ctx
 * @param keep_alive_time_secs
 */
void iot_mqtt_set_keep_alive_time_secs(iot_mqtt_ctx_t *mqtt_ctx, uint16_t keep_alive_time_secs) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->keep_alive_time_secs = keep_alive_time_secs;
}

/**
 * 设置 ping 的超市时间 默认 3000ms
 * @param mqtt_ctx
 * @param time_out
 */
void iot_mqtt_set_ping_timeout_ms(iot_mqtt_ctx_t *mqtt_ctx, uint32_t time_out) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->ping_timeout_ms = time_out;
}

/**
 * 建联时 是否  clean_session
 * @param mqtt_ctx
 * @param clean_session
 */
void iot_mqtt_set_clean_session(iot_mqtt_ctx_t *mqtt_ctx, bool clean_session) {
    if (mqtt_ctx == NULL) {
        return;
    }
    mqtt_ctx->clean_session = clean_session;
}


static void _s_iot_on_connection_interrupted(struct aws_mqtt_client_connection *connection, int error_code, void *userdata) {
    LOGD(TAG_IOT_MQTT, "_s_iot_on_connection_interrupted error_code = %d userdata = %p", error_code, userdata);
    iot_mqtt_ctx_t *ctx = userdata;
    ctx->isConnected = false;

    iot_mqtt_event_data_t data = {.error_code = error_code};
    _s_call_back_event(ctx, IOT_MQTTEVT_DISCONNECT, data);
}

static void _s_iot_on_connection_resumed(
        struct aws_mqtt_client_connection *connection,
        enum aws_mqtt_connect_return_code return_code,
        bool session_present,
        void *userdata) {
    iot_mqtt_ctx_t *ctx = userdata;
    ctx->isConnected = true;
    LOGD(TAG_IOT_MQTT, "_s_iot_on_connection_resumed");
    iot_mqtt_event_data_t data = {0};
    _s_call_back_event(ctx, IOT_MQTTEVT_RECONNECT, data);
}

void _s_call_back_event(iot_mqtt_ctx_t *ctx, iot_mqtt_event_type_t event_type, iot_mqtt_event_data_t event_data) {
    ctx->last_event_data = event_data;
    if (ctx->default_mqtt_event_callback_fn != NULL) {
        ctx->default_mqtt_event_callback_fn(ctx, event_type, event_data, ctx->default_mqtt_event_callback_fn_user_data);
    }
}

static void _s_iot_on_any_publish_handler_fn(
        struct aws_mqtt_client_connection *connection,
        const struct aws_byte_cursor *topic,
        const struct aws_byte_cursor *payload,
        bool dup,
        enum aws_mqtt_qos qos,
        bool retain,
        void *userdata) {
//    LOGD(TAG_IOT_MQTT, "_s_iot_on_any_publish_handler_fn topic = %.*s payload = %.*s ", AWS_BYTE_CURSOR_PRI(*topic),
//         AWS_BYTE_CURSOR_PRI(*payload));
    iot_mqtt_ctx_t *ctx = userdata;

    iot_mqtt_pub_data_t pub_data;
    pub_data.qos = qos;
    pub_data.topic = topic->ptr;
    pub_data.topic_len = topic->len;
    pub_data.payload = payload->ptr;
    pub_data.payload_len = payload->len;

    if (ctx->global_topic_handler_fn_list != NULL && !aws_linked_list_empty(ctx->global_topic_handler_fn_list)) {
        for (struct aws_linked_list_node *iter = aws_linked_list_begin(ctx->global_topic_handler_fn_list); iter != aws_linked_list_end(ctx->global_topic_handler_fn_list);
             iter = aws_linked_list_next(iter)) {
            iot_mqtt_topic_handler_fn *topic_handler_fn = AWS_CONTAINER_OF(iter, iot_mqtt_sub_topic_map_item_t, node)->handler_fn;
            void *topic_handler_fn_user_data = AWS_CONTAINER_OF(iter, iot_mqtt_sub_topic_map_item_t, node)->user_data;
            topic_handler_fn(ctx, &pub_data, topic_handler_fn_user_data);
        }
    }
}


static void _s_iot_on_connection_complete_fn(
        struct aws_mqtt_client_connection *connection,
        int error_code,
        enum aws_mqtt_connect_return_code return_code,
        bool session_present,
        void *userdata) {
    LOGD(TAG_IOT_MQTT, "_s_iot_on_connection_complete_fn error_code = %d return_code = %d ", error_code, return_code);
    iot_mqtt_ctx_t *ctx = userdata;
    aws_mutex_lock(&ctx->lock);
    iot_mqtt_event_data_t event_data = {.error_code = error_code, .return_code = return_code};
    ctx->last_event_data = event_data;
    ctx->is_connection_complete = true;
    aws_condition_variable_notify_all(&ctx->cvar);
    if (error_code == 0 || return_code == 0) {
        ctx->isConnected = true;
        _s_call_back_event(ctx, IOT_MQTTEVT_CONNECT, event_data);
    } else {
        ctx->isConnected = false;
        _s_call_back_event(ctx, IOT_MQTTEVT_CONNECT_ERROR, event_data);
    }
    aws_mutex_unlock(&ctx->lock);

}


int dynamic_register(iot_mqtt_ctx_t *mqtt_ctx) {
    int ret = CODE_SUCCESS;
    int32_t randomNum = arenal_get_random_num();
    struct aws_date_time test_time;
    aws_date_time_init_now(&test_time);
    uint64_t timeMils = aws_date_time_as_millis(&test_time);
    struct iot_mqtt_dynamic_register_basic_param registerParam = {
            .instance_id = aws_string_c_str(mqtt_ctx->instance_id),
            .auth_type = mqtt_ctx->auth_type,
            .timestamp = timeMils,
            .random_num = randomNum,
            .product_key = aws_string_c_str(mqtt_ctx->product_key),
            .device_name = aws_string_c_str(mqtt_ctx->device_name)
    };

    struct aws_string *sign = _iot_mqtt_hmac_sha256_encrypt(mqtt_ctx->alloc, &registerParam, aws_string_c_str(mqtt_ctx->product_secret));

    // json 数据
    struct aws_json_value *post_data_json = aws_json_value_new_object(mqtt_ctx->alloc);
    aws_json_add_aws_string_val1(mqtt_ctx->alloc, post_data_json, "InstanceID", mqtt_ctx->instance_id);
    aws_json_add_aws_string_val1(mqtt_ctx->alloc, post_data_json, "product_key", mqtt_ctx->product_key);
    aws_json_add_aws_string_val1(mqtt_ctx->alloc, post_data_json, "device_name", mqtt_ctx->device_name);
    aws_json_add_num_val1(mqtt_ctx->alloc, post_data_json, "random_num", registerParam.random_num);
    aws_json_add_num_val1(mqtt_ctx->alloc, post_data_json, "timestamp", registerParam.timestamp);
    aws_json_add_num_val1(mqtt_ctx->alloc, post_data_json, "auth_type", mqtt_ctx->auth_type);
    aws_json_add_aws_string_val1(mqtt_ctx->alloc, post_data_json, "signature", sign);
    aws_string_destroy_secure(sign);


    // http 请求 url + path + query 参数
    char url_str[1024];
    AWS_ZERO_ARRAY(url_str);
    struct aws_byte_buf url_str_buf = aws_byte_buf_from_empty_array(url_str, sizeof(url_str));
    aws_byte_buf_write_from_whole_cursor(&url_str_buf, aws_byte_cursor_from_c_str("https://"));
    aws_byte_buf_write_from_whole_cursor(&url_str_buf, aws_byte_cursor_from_string(mqtt_ctx->http_host));
    aws_byte_buf_write_from_whole_cursor(&url_str_buf, aws_byte_cursor_from_c_str(DYNAMIC_REGISTER_PATH));
    aws_byte_buf_write_from_whole_cursor(&url_str_buf, aws_byte_cursor_from_c_str("?"));
    aws_byte_buf_write_from_whole_cursor(&url_str_buf, aws_byte_cursor_from_c_str(API_ACTION_DYNAMIC_REGISTER));
    aws_byte_buf_write_from_whole_cursor(&url_str_buf, aws_byte_cursor_from_c_str("&"));
    aws_byte_buf_write_from_whole_cursor(&url_str_buf, aws_byte_cursor_from_c_str(API_VERSION_QUERY_PARAM));
    // add query params

    LOGD(TAG_IOT_MQTT, "dynamic_register url_str_buf = %s", url_str);
    struct iot_http_request_context *http_ctx = iot_new_http_ctx(mqtt_ctx->alloc);
    iot_http_ctx_set_url(http_ctx, url_str);
    iot_http_ctx_set_method(http_ctx, POST);
    struct aws_byte_buf post_data_json_buf = aws_json_obj_to_bye_buf(mqtt_ctx->alloc, post_data_json);
    char *post_data_str = aws_buf_to_char_str(mqtt_ctx->alloc, &post_data_json_buf);
    iot_http_ctx_set_json_body(http_ctx, post_data_str);
    struct iot_http_response *response = iot_http_request(http_ctx);
    LOGE(TAG_IOT_MQTT, "dynamic_register response = %.*s", (response->response_body));

    aws_byte_buf_clean_up(&url_str_buf);
    aws_json_value_destroy(post_data_json);
    aws_byte_buf_clean_up(&post_data_json_buf);
    aws_mem_release(mqtt_ctx->alloc, post_data_str);
    iot_http_response_dynamic_register_t *result = _parse_dynamic_register(mqtt_ctx->alloc, response);


    if (result->meta_info.responseMetaDataError.Code == 0 && result->result.len > 0) {
        struct aws_string *decode_data = aes_decode(mqtt_ctx->alloc, aws_string_c_str(mqtt_ctx->product_secret), result->result.payload);
        mqtt_ctx->device_secret = decode_data;
        goto done;
    } else {
        ret = CODE_MQTT_CONNECT_DYNAMIC_REGISTER_REQUEST_ERROR;
        goto done;
    }

    done:
    iot_http_response_release(response);
    aws_mem_release(mqtt_ctx->alloc, result);
    return ret;
}


iot_http_response_dynamic_register_t *_parse_dynamic_register(struct aws_allocator *allocator, struct iot_http_response *response) {
    iot_http_response_dynamic_register_t *dynamic_register_res = aws_mem_calloc(allocator, 1, sizeof(iot_http_response_dynamic_register_t));

    if (response->error_code != 0) {
        dynamic_register_res->meta_info.responseMetaDataError.CodeN = response->error_code;
        dynamic_register_res->meta_info.responseMetaDataError.Message = "http request failed";
    }


    struct aws_byte_cursor response_json_cur = aws_byte_cursor_from_buf(&response->response_body);
    struct aws_json_value *response_json = aws_json_value_new_from_string(allocator, response_json_cur);
    struct aws_json_value *result_json = aws_json_value_get_from_object(response_json, aws_byte_cursor_from_c_str("Result"));
    struct aws_json_value *metadata_json = aws_json_value_get_from_object(response_json, aws_byte_cursor_from_c_str("ResponseMetadata"));

    dynamic_register_res->meta_info.action = aws_json_get_str(allocator, metadata_json, "Action");
    dynamic_register_res->meta_info.version = aws_json_get_str(allocator, metadata_json, "Version");

    if (aws_json_value_has_key(metadata_json, aws_byte_cursor_from_c_str("Error"))) {
        struct aws_json_value *error_json = aws_json_value_get_from_object(metadata_json, aws_byte_cursor_from_c_str("Error"));
        if (error_json != NULL) {
            dynamic_register_res->meta_info.responseMetaDataError.Code = aws_json_get_str(allocator, error_json, "Code");
            dynamic_register_res->meta_info.responseMetaDataError.CodeN = (int32_t) aws_json_get_num_val(error_json, "CodeN");
            dynamic_register_res->meta_info.responseMetaDataError.Message = aws_json_get_str(allocator, error_json, "Message");

        }
    }
    dynamic_register_res->result.len = (int32_t) aws_json_get_num_val(result_json, "len");
    dynamic_register_res->result.payload = aws_json_get_str(allocator, result_json, "payload");

    return dynamic_register_res;
}


int32_t iot_connect(iot_mqtt_ctx_t *mqtt_ctx) {
    int ret = 0;
    if (!aws_string_is_valid(mqtt_ctx->host)) {
        return CODE_MQTT_CONNECT_DEVICE_INFO_INVALID;
    }

    if (mqtt_ctx->port <= 0) {
        return CODE_MQTT_CONNECT_PORT_INVALID;
    }

    switch (mqtt_ctx->auth_type) {
        case IOT_AUTH_DEVICE_SECRET:
            // 就服务端而言只有两种 模式,  这处理针对 VerifyModeDeviceSecret 做特殊处理
            mqtt_ctx->auth_type = IOT_AUTH_DYNAMIC_PRE_REGISTERED;
            if (!aws_string_is_valid(mqtt_ctx->product_key)
                || !aws_string_is_valid(mqtt_ctx->device_name)
                || !aws_string_is_valid(mqtt_ctx->device_secret)) {
                return CODE_MQTT_CONNECT_DEVICE_INFO_INVALID;
            }

            break;
        case IOT_AUTH_DYNAMIC_PRE_REGISTERED:
        case IOT_AUTH_DYNAMIC_NO_PRE_REGISTERED:
            if (!aws_string_is_valid(mqtt_ctx->product_key)
                || !aws_string_is_valid(mqtt_ctx->product_secret)
                || !aws_string_is_valid(mqtt_ctx->device_name)) {
                return CODE_MQTT_CONNECT_DEVICE_INFO_INVALID;
            }

            int dynamic_register_result = dynamic_register(mqtt_ctx);
            if (dynamic_register_result != CODE_SUCCESS) {
                return dynamic_register_result;
            }
            break;
    }


    mqtt_ctx->mqtt_client = aws_mqtt_client_new(mqtt_ctx->alloc, get_iot_core_context()->client_bootstrap);
    mqtt_ctx->mqtt_connection = aws_mqtt_client_connection_new(mqtt_ctx->mqtt_client);

    aws_mqtt_client_connection_set_connection_interruption_handlers(mqtt_ctx->mqtt_connection, _s_iot_on_connection_interrupted, mqtt_ctx, _s_iot_on_connection_resumed,
                                                                    mqtt_ctx);
    aws_mqtt_client_connection_set_on_any_publish_handler(mqtt_ctx->mqtt_connection, _s_iot_on_any_publish_handler_fn, mqtt_ctx);
    mqtt_ctx->client_id = _iot_get_client_id(mqtt_ctx);
    mqtt_ctx->user_name = _iot_get_user_name(mqtt_ctx);
    mqtt_ctx->user_password = _iot_mqtt_get_password(mqtt_ctx);


    struct aws_mqtt_connection_options *connection_options = aws_mem_acquire(mqtt_ctx->alloc, sizeof(struct aws_mqtt_connection_options));
    AWS_ZERO_STRUCT(*connection_options);
    mqtt_ctx->connection_options = connection_options;

    connection_options->user_data = mqtt_ctx;
    connection_options->clean_session = mqtt_ctx->clean_session;

    connection_options->client_id = aws_byte_cursor_from_string(mqtt_ctx->client_id);
    connection_options->host_name = aws_byte_cursor_from_string(mqtt_ctx->host);
    connection_options->port = mqtt_ctx->port;
    connection_options->keep_alive_time_secs = mqtt_ctx->keep_alive_time_secs;
    connection_options->ping_timeout_ms = mqtt_ctx->ping_timeout_ms;
    connection_options->on_connection_complete = _s_iot_on_connection_complete_fn;
    mqtt_ctx->socket_options.connect_timeout_ms = mqtt_ctx->connect_timeout_ms;
    mqtt_ctx->socket_options.domain = AWS_SOCKET_IPV4;
    connection_options->socket_options = &mqtt_ctx->socket_options;

    // TODO tls 处理
    if (mqtt_ctx->isTls) {
        struct aws_tls_ctx_options tls_ctx_opt;
        struct aws_byte_cursor caCur = aws_byte_cursor_from_c_str(g_mqtt_ca);
        aws_tls_ctx_options_init_default_client(&tls_ctx_opt, mqtt_ctx->alloc);
        aws_tls_ctx_options_override_default_trust_store(&tls_ctx_opt, &caCur);
        tls_ctx_opt.verify_peer = false;
        mqtt_ctx->tls_ctx = aws_tls_client_ctx_new(mqtt_ctx->alloc, &tls_ctx_opt);
        aws_tls_connection_options_init_from_ctx(&mqtt_ctx->tls_connection_options, mqtt_ctx->tls_ctx);
        connection_options->tls_options = &mqtt_ctx->tls_connection_options;
        aws_tls_ctx_options_clean_up(&tls_ctx_opt);
    }

    struct aws_byte_cursor username_cur = aws_byte_cursor_from_string(mqtt_ctx->user_name);
    struct aws_byte_cursor password_cur = aws_byte_cursor_from_string(mqtt_ctx->user_password);
    aws_mqtt_client_connection_set_login(mqtt_ctx->mqtt_connection, &username_cur, &password_cur);
    ret = aws_mqtt_client_connection_connect(mqtt_ctx->mqtt_connection, connection_options);
    LOGE(TAG_IOT_MQTT, "aws_mqtt_client_connection_connect error code %d", ret);
    if (ret != AWS_OP_SUCCESS) {
        return CODE_MQTT_CONNECT_AWS_INNER_ERROR;
    }

    // 等待连接完成
    aws_condition_variable_wait_pred(&mqtt_ctx->cvar, &mqtt_ctx->lock, _s_waite_connect_complete, mqtt_ctx);
    LOGE(TAG_IOT_MQTT, "aws_condition_variable_wait_pred _s_waite_connect_complete");
    if (mqtt_ctx->last_event_data.error_code == 0 && mqtt_ctx->last_event_data.return_code == 0) {
        // 连接成功
        return CODE_SUCCESS;
    }

    // 连接失败
    if (mqtt_ctx->last_event_data.return_code != 0) {
        return mqtt_ctx->last_event_data.return_code;
    }
    if (mqtt_ctx->last_event_data.error_code != 0) {
        return mqtt_ctx->last_event_data.error_code;
    }

}


static bool _s_waite_connect_complete(void *context) {
    iot_mqtt_ctx_t *mqtt_ctx = (iot_mqtt_ctx_t *) context;
    return mqtt_ctx->is_connection_complete;
}


int32_t iot_mqtt_sub(iot_mqtt_ctx_t *ctx, char *topic, uint8_t qos, aws_mqtt_client_publish_received_fn handler, void *userdata) {
    if (ctx == NULL || ctx->mqtt_connection == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }

    const struct aws_byte_cursor cur = aws_byte_cursor_from_c_str(topic);
    aws_mqtt_client_connection_subscribe(ctx->mqtt_connection, &cur, qos, handler, userdata, NULL, NULL, NULL);

}

int32_t iot_mqtt_unsub(iot_mqtt_ctx_t* ctx, char* topic, uint8_t qos, aws_mqtt_op_complete_fn handler, void* userdata) {
    if (ctx == NULL || ctx->mqtt_connection == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    const struct aws_byte_cursor cur = aws_byte_cursor_from_c_str(topic);
    aws_mqtt_client_connection_unsubscribe(ctx->mqtt_connection, &cur,handler, userdata);
    return 0;
}


int32_t iot_mqtt_sub_with_topic_map(iot_mqtt_ctx_t *ctx, iot_mqtt_topic_map_t *topic_map) {
    if (ctx == NULL || ctx->mqtt_connection == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    const struct aws_byte_cursor cur = aws_byte_cursor_from_c_str(topic_map->topic);
    aws_mqtt_client_connection_subscribe(ctx->mqtt_connection, &cur, 1, topic_map->handler, topic_map->userdata, NULL, NULL, NULL);
}

// 获取 clientId
struct aws_string *_iot_get_client_id(iot_mqtt_ctx_t *mqtt_ctx) {
    int length = strlen(aws_string_c_str(mqtt_ctx->product_key)) + strlen(aws_string_c_str(mqtt_ctx->device_name)) + 10;
    char clientIdStr[length];
    sprintf(clientIdStr, "%s|%s", aws_string_c_str(mqtt_ctx->product_key), aws_string_c_str(mqtt_ctx->device_name));
    LOGD(TAG_IOT_MQTT, "arenal_get_client_id = %s", clientIdStr);
    return aws_string_new_from_c_str(mqtt_ctx->alloc, clientIdStr);
}


struct aws_string *_iot_get_user_name(iot_mqtt_ctx_t *mqtt_ctx) {
    return get_user_name(mqtt_ctx->alloc, mqtt_ctx->product_key, mqtt_ctx->device_name);
}


struct aws_string *_iot_mqtt_hmac_sha256_encrypt(struct aws_allocator *allocator, struct iot_mqtt_dynamic_register_basic_param *registerBasicParam, const char *secret) {
    char inputStr[256];
    sprintf(inputStr, "auth_type=%d&device_name=%s&random_num=%d&product_key=%s&timestamp=%llu",
            registerBasicParam->auth_type, registerBasicParam->device_name, registerBasicParam->random_num,
            registerBasicParam->product_key, registerBasicParam->timestamp);

    struct aws_byte_cursor secretBuff = aws_byte_cursor_from_c_str(secret);
    struct aws_byte_cursor inputBuff = aws_byte_cursor_from_c_str(inputStr);

    uint8_t output[AWS_SHA256_HMAC_LEN] = {0};
    struct aws_byte_buf sha256buf = aws_byte_buf_from_array(output, sizeof(output));
    sha256buf.len = 0;
    aws_sha256_hmac_compute(allocator, &secretBuff, &inputBuff, &sha256buf, 0);


    size_t terminated_length = 0;
    aws_base64_compute_encoded_len(sha256buf.len, &terminated_length);

    struct aws_byte_buf byte_buf;
    aws_byte_buf_init(&byte_buf, allocator, terminated_length + 2);

    struct aws_byte_cursor sha256Cur = aws_byte_cursor_from_buf(&sha256buf);
    aws_base64_encode(&sha256Cur, &byte_buf);

    struct aws_string *encrypt_string = aws_string_new_from_buf(allocator, &byte_buf);
    aws_byte_buf_clean_up(&byte_buf);

    return encrypt_string;
}


struct aws_string *_iot_mqtt_get_password(iot_mqtt_ctx_t *mqtt_ctx) {
    int32_t randomNum = arenal_get_random_num();

    struct aws_date_time test_time;
    aws_date_time_init_now(&test_time);
    uint64_t timeMils = aws_date_time_as_millis(&test_time);

    struct iot_mqtt_dynamic_register_basic_param registerParam = {
            .auth_type = mqtt_ctx->auth_type,
            .timestamp = timeMils,
            .random_num = randomNum,
            .product_key = aws_string_c_str(mqtt_ctx->product_key),
            .device_name = aws_string_c_str(mqtt_ctx->device_name)
    };

    LOGD(TAG_IOT_MQTT, "arenal_get_password randomNum = %d timeMils = %llu", randomNum, timeMils);

    struct aws_string *sign = _iot_mqtt_hmac_sha256_encrypt(mqtt_ctx->alloc, &registerParam, aws_string_c_str(mqtt_ctx->device_secret));
    char values[500];
    sprintf(values, "%d|%d|%llu|%s", mqtt_ctx->auth_type, randomNum, timeMils, aws_string_c_str(sign));
    aws_string_destroy_secure(sign);
    LOGD(TAG_IOT_MQTT, "arenal_get_password = %s", values);
    return aws_string_new_from_c_str(mqtt_ctx->alloc, values);
}

int32_t iot_mqtt_disconnect(iot_mqtt_ctx_t *mqtt_ctx) {
    if (mqtt_ctx == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    int ret = aws_mqtt_client_connection_disconnect(mqtt_ctx->mqtt_connection, NULL, NULL);
    if (ret != AWS_OP_SUCCESS) {
        return CODE_MQTT_DISCONNECT_FAILED;
    }
    return CODE_SUCCESS;
}


void iot_mqtt_clean(iot_mqtt_ctx_t *mqtt_ctx) {
    aws_string_destroy_secure(mqtt_ctx->product_key);
    aws_string_destroy_secure(mqtt_ctx->product_secret);
    aws_string_destroy_secure(mqtt_ctx->device_name);
    aws_string_destroy_secure(mqtt_ctx->device_secret);
    aws_string_destroy_secure(mqtt_ctx->client_id);
    aws_string_destroy_secure(mqtt_ctx->user_name);
    aws_string_destroy_secure(mqtt_ctx->user_password);
    aws_condition_variable_clean_up(&mqtt_ctx->cvar);
    aws_mutex_clean_up(&mqtt_ctx->lock);
    aws_mqtt_client_connection_release(mqtt_ctx->mqtt_connection);
    aws_mqtt_client_release(mqtt_ctx->mqtt_client);
    aws_mem_release(mqtt_ctx->alloc, mqtt_ctx->connection_options);
}
