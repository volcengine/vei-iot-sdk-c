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

#ifndef ARENAL_IOT_IOT_CORE_HEADER_H
#define ARENAL_IOT_IOT_CORE_HEADER_H

#include <aws/mqtt/mqtt.h>
#include <aws/mqtt/client.h>
#include <aws/cal/hmac.h>
#include <aws/common/encoding.h>
#include <aws/common/json.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/socket.h>
#include <aws/common/byte_buf.h>
#include <aws/http/http.h>
#include <aws/io/uri.h>
#include <aws/io/socket.h>
#include <aws/common/clock.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/http/connection.h>
#include <aws/http/proxy.h>
#include <aws/io/logging.h>
#include <aws/common/string.h>
#include <aws/common/common.h>
#include <aws/common/logging.h>
#include <aws/common/stdint.h>
#include <aws/common/stdbool.h>
#include <aws/common/string.h>
#include <openssl/aes.h>
#include <stddef.h>
#include <stdbool.h>
#include "iot_mqtt.h"
#include "iot_core.h"

#define SDK_VERSION "1.0.0"

#define DYNAMIC_REGISTER_PATH "/2021-12-14/DynamicRegister"

#define API_VERSION = "2021-12-14"
#define API_VERSION_QUERY_PARAM "Version=2021-12-14"
#define API_ACTION_DYNAMIC_REGISTER  "Action=DynamicRegister"

// iot_core.c
typedef struct core_context {
    struct aws_allocator *alloc;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;
    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;
    struct aws_client_bootstrap *client_bootstrap;
    struct aws_logger logger;
    struct aws_thread_scheduler *thread_scheduler;
    struct aws_task_scheduler scheduler;
    // save sub device gateway
    struct aws_hash_table device_secret_map;

} core_context_t;

void iot_core_post_delay_task(struct aws_task *task, uint64_t delay_time_sec);



// iot_mqtt.c
typedef struct sub_topic_handler_map_item {
    iot_mqtt_topic_handler_fn *handler_fn;
    void *user_data;
    struct aws_linked_list_node node;
} iot_mqtt_sub_topic_map_item_t;


typedef struct iot_mqtt_ctx {
    struct aws_allocator *alloc;
    struct aws_string *host;
    struct aws_string *http_host;
    int32_t port;
    bool isTls;
    struct aws_string *instance_id;
    struct aws_string *product_key;
    struct aws_string *product_secret;
    struct aws_string *device_name;
    struct aws_string *device_secret;
    iot_mqtt_auth_type_t auth_type;
    bool clean_session;
    uint32_t connect_timeout_ms;
    uint16_t keep_alive_time_secs;
    uint32_t ping_timeout_ms;
    iot_mqtt_event_callback_fn *default_mqtt_event_callback_fn;
    void *default_mqtt_event_callback_fn_user_data;

    struct aws_linked_list *global_topic_handler_fn_list;
    struct aws_hash_table *sub_topic_handler_map;

    struct aws_string *client_id;
    struct aws_string *user_name;
    struct aws_string *user_password;

    struct aws_condition_variable cvar;
    struct aws_mutex lock;
    bool isConnected;
    bool is_connection_complete;

    struct aws_mqtt_client *mqtt_client;
    struct aws_mqtt_client_connection *mqtt_connection;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_mqtt_connection_options *connection_options;
    struct aws_socket_options socket_options;
    iot_mqtt_event_data_t last_event_data;

    // 一个 topic  只是多个订阅者

    struct aws_tls_ctx *tls_ctx;
    struct aws_tls_ctx_options tls_ctx_options;

    // 全局的 topic_handler 也支持多个

} iot_mqtt_ctx_t;

typedef struct {
    char *topic;
    aws_mqtt_client_publish_received_fn *handler;
    void *userdata;
} iot_mqtt_topic_map_t;



static bool _s_waite_connect_complete(void *context);

int32_t iot_mqtt_sub(iot_mqtt_ctx_t *ctx, char *topic, uint8_t qos, aws_mqtt_client_publish_received_fn handler, void *userdata);

int32_t iot_mqtt_unsub(iot_mqtt_ctx_t* ctx, char* topic, uint8_t qos, aws_mqtt_op_complete_fn handler, void* userdata);

int32_t iot_mqtt_sub_with_topic_map(iot_mqtt_ctx_t *ctx, iot_mqtt_topic_map_t *topic_map);


struct aws_string *_iot_get_client_id(iot_mqtt_ctx_t *mqtt_ctx);

struct aws_string *_iot_get_user_name(iot_mqtt_ctx_t *mqtt_ctx);

struct aws_string *_iot_mqtt_hmac_sha256_encrypt(struct aws_allocator *allocator, struct iot_mqtt_dynamic_register_basic_param *registerBasicParam, const char *secret);

struct aws_string *_iot_mqtt_get_password(iot_mqtt_ctx_t *mqtt_ctx);


void _s_call_back_event(iot_mqtt_ctx_t *ctx, iot_mqtt_event_type_t event_type, iot_mqtt_event_data_t event_data);

static void _s_iot_on_connection_interrupted(struct aws_mqtt_client_connection *connection, int error_code, void *userdata);

static void _s_iot_on_connection_resumed(
        struct aws_mqtt_client_connection *connection,
        enum aws_mqtt_connect_return_code return_code,
        bool session_present,
        void *userdata);

static void _s_iot_on_connection_complete_fn(
        struct aws_mqtt_client_connection *connection,
        int error_code,
        enum aws_mqtt_connect_return_code return_code,
        bool session_present,
        void *userdata);

static void _s_iot_on_any_publish_handler_fn(
        struct aws_mqtt_client_connection *connection,
        const struct aws_byte_cursor *topic,
        const struct aws_byte_cursor *payload,
        bool dup,
        enum aws_mqtt_qos qos,
        bool retain,
        void *userdata);


iot_http_response_dynamic_register_t *_parse_dynamic_register(struct aws_allocator *allocator, struct iot_http_response *response);


// iot_http.c

typedef void (iot_http_on_get_header)(const struct aws_http_header *header_array,
                                      size_t num_headers,
                                      void *user_data);

typedef struct iot_http_request_context {
    core_context_t *core_ctx;
    struct aws_allocator *alloc;
    struct aws_string *url;
    enum iot_http_method method;
    struct aws_http_headers *headers;
    struct aws_string *json_body;
    void *user_data;
    int32_t connect_timeout_ms;
    bool is_asyn_request;

    iot_http_request_asyn_callback *callback;
    void *callback_user_data;

    struct aws_uri *uri;
    struct aws_tls_connection_options tls_connection_options;
    struct aws_http_connection *client_connection;

    struct aws_http_message *http_request_message;
    struct aws_byte_cursor body_cur;
    struct aws_input_stream *post_body_stream;
    struct aws_http_stream *stream;

    iot_http_response_t *response;
    aws_http_on_incoming_body_fn *on_response_body;
    aws_http_on_stream_complete_fn *on_complete;
    iot_http_on_get_header *on_get_header;

    bool stream_complete;
    bool client_connection_is_shutdown;
    bool is_connection_complete;

    struct aws_mutex data_mutex;
    struct aws_mutex connection_mutex;
    struct aws_mutex response_lock;
    struct aws_condition_variable wait_connection_cvar;
    struct aws_condition_variable wait_response_cvar;
    int wait_connection_result;
    bool has_request;


} iot_http_request_context_t;

struct iot_http_response *_http_request_inner(iot_http_request_context_t *http_context);

void _s_init_http_response(iot_http_request_context_t *http_context);

static int _s_on_stream_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data);

static void _s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data);

void _do_request(iot_http_request_context_t *http_context);

static bool _s_waite_connect(void *context);

void _http_ctx_set_on_response_body(iot_http_request_context_t *ctx, aws_http_on_incoming_body_fn *on_response_body);

void _http_ctx_set_on_complete(iot_http_request_context_t *ctx, aws_http_on_stream_complete_fn *on_complete);

void _http_ctx_set_on_get_header(iot_http_request_context_t *http_ctx, iot_http_on_get_header *on_get_header);

static void _s_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data);

static void _s_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data);

void _call_back_response(iot_http_request_context_t *ctx);


// iot_log.c
typedef void(iot_on_log_save_fn)(struct aws_array_list *log_lines, void *userdata);

struct iot_log_ctx {
    struct aws_allocator *allocator;
    char *save_dir_path;
    struct aws_mutex sync;
    struct aws_thread background_thread;
    struct aws_array_list pending_log_lines;
    struct aws_condition_variable pending_line_signal;
    FILE *log_file;
    struct aws_string *file_path;
    struct aws_task *send_log_task;
    bool isTimeToSendLog;
    bool finished;
    iot_on_log_save_fn *on_log_save_fn;
    void *on_log_save_fn_user_data;
    struct iot_log_ctx_option option;
} ;

void iot_log_set_on_log_save_fn(iot_on_log_save_fn *on_save_fn, void *user_data);

struct aws_string *iot_get_log_file_name();

static void _s_background_thread_writer(void *thread_data);

void _log_format(enum aiot_log_level level, struct iot_log_obj *logObj, const char *logType, const char *tag,
                 const char *format,
                 va_list format_args);

static int _s_background_channel_send(struct iot_log_ctx *impl, struct iot_log_obj *logObj);

void _check_file();

void _log_level_to_string(enum aiot_log_level log_level, const char **level_string);

enum aiot_log_level _log_string_to_level(struct aws_byte_cursor *lowest_level_cur);
#endif //ARENAL_IOT_IOT_CORE_HEADER_H
