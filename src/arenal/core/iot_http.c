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

#include <aws/io/stream.h>
#include <aws/common/byte_buf.h>
#include "iot_http.h"
#include "iot_log.h"
#include "iot_code.h"
#include "iot_util.h"
#include "iot_core_header.h"


static bool use_local_proxy = false;

iot_http_request_context_t *iot_new_http_ctx() {
    iot_core_init();
    core_context_t *core_ctx = get_iot_core_context();
    if (core_ctx == NULL) {
        // 未初始化
        return NULL;
    }
    iot_http_request_context_t *http_context = aws_mem_calloc(core_ctx->alloc, 1, sizeof(iot_http_request_context_t));
    http_context->core_ctx = get_iot_core_context();
    http_context->alloc = core_ctx->alloc;

    // 设置超时时间
    http_context->connect_timeout_ms = HTTPS_DEFAULT_CONNECTION_TIME_OUT;

    // 锁初始化
    aws_mutex_init(&http_context->data_mutex);
    aws_mutex_init(&http_context->connection_mutex);
    aws_mutex_init(&http_context->response_lock);
    aws_condition_variable_init(&http_context->wait_connection_cvar);
    aws_condition_variable_init(&http_context->wait_response_cvar);

    return http_context;
}

void iot_http_ctx_set_url(iot_http_request_context_t *ctx, char *url) {
    ctx->url = aws_string_new_from_c_str(ctx->alloc, url);
}

void iot_http_ctx_add_header(iot_http_request_context_t *ctx, char *key, char *value) {
    if (ctx->headers == NULL) {
        ctx->headers = aws_http_headers_new(ctx->alloc);
    }
    aws_http_headers_add(ctx->headers, aws_byte_cursor_from_c_str(key), aws_byte_cursor_from_c_str(value));
}

void iot_http_ctx_set_method(iot_http_request_context_t *ctx, enum iot_http_method method) {
    ctx->method = method;
}

void iot_http_ctx_set_json_body(iot_http_request_context_t *ctx, char *json_body) {
    ctx->json_body = aws_string_new_from_c_str(ctx->alloc, json_body);
}

void iot_http_ctx_set_user_data(iot_http_request_context_t *ctx, void *user_data) {
    ctx->user_data = user_data;
}

void iot_http_ctx_set_connect_time_out_mil(iot_http_request_context_t *ctx, int32_t time_mil) {
    ctx->connect_timeout_ms = time_mil;
}

void _http_ctx_set_on_response_body(iot_http_request_context_t *http_ctx, aws_http_on_incoming_body_fn *on_response_body) {
    http_ctx->on_response_body = on_response_body;
}

void _http_ctx_set_on_complete(iot_http_request_context_t *http_ctx, aws_http_on_stream_complete_fn *on_complete) {
    http_ctx->on_complete = on_complete;
}


void _http_ctx_set_on_get_header(iot_http_request_context_t *http_ctx, iot_http_on_get_header *on_get_header) {
    http_ctx->on_get_header = on_get_header;
}


/**
 * http 连接建立之后的回调
 * @param connection
 * @param error_code
 * @param user_data
 */
static void _s_on_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    LOGD(IOT_TAG_HTTP, "_s_on_connection_setup error_code = %d ", error_code);
    iot_http_request_context_t *http_ctx = user_data;
    bool lock_succ = aws_mutex_try_lock(&http_ctx->connection_mutex) == AWS_OP_SUCCESS;
    http_ctx->client_connection = connection;// TODO 在弱网环境下, 这里可能为空
    http_ctx->wait_connection_result = error_code;
    http_ctx->response->inner_error_code = error_code;
    http_ctx->is_connection_complete = true;
    // 信号通知请求完成
    aws_condition_variable_notify_one(&http_ctx->wait_connection_cvar);
    if (lock_succ) {
        aws_mutex_unlock(&http_ctx->connection_mutex);
    }

    // 当前是在其他线程 异步发起网络请求
    if (http_ctx->is_asyn_request) {
        if (error_code == 0 && connection != NULL) {
            _do_request(http_ctx);
        } else {
            http_ctx->response->error_code = CODE_HTTP_CLIENT_CONNECT_ERROR;
            // 回调建立连接失败
            _call_back_response(http_ctx);
        }
    }
    // 连接建立失败
    if (connection == NULL || error_code != 0) {
        iot_clean_http(http_ctx);
    }
}


/**
 * 连接关闭, 或链接失败的回调, 用来清理内存
 * @param connection
 * @param error_code
 * @param user_data
 */
static void _s_on_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    iot_http_request_context_t *http_ctx = user_data;
    LOGD(IOT_TAG_HTTP, "_s_on_connection_shutdown 连接关闭");
    bool lock_succ = aws_mutex_try_lock(&http_ctx->data_mutex) == AWS_OP_SUCCESS;
    http_ctx->client_connection_is_shutdown = true;
    http_ctx->is_connection_complete = true;
    http_ctx->wait_connection_result = error_code;
    aws_condition_variable_notify_one(&http_ctx->wait_connection_cvar);
    if (lock_succ) {
        aws_mutex_unlock(&http_ctx->data_mutex);
    }
    iot_clean_http(http_ctx);
}

/**
 * 等待连接建立完成
 * @param context
 * @return
 */
static bool _s_waite_connect(void *context) {
    iot_http_request_context_t *http_context = (iot_http_request_context_t *) context;
    return http_context->is_connection_complete;
}


/**
 * 发起异步网络请求
 * @param http_context
 * @param callback
 * @param userdata
 * @return
 */
int iot_http_request_asyn(iot_http_request_context_t *http_context, iot_http_request_asyn_callback *callback, void *userdata) {
    http_context->is_asyn_request = true;
    http_context->callback = callback;
    http_context->callback_user_data = userdata;
    iot_http_request(http_context);
    return CODE_SUCCESS;

}

iot_http_response_t *iot_http_request(iot_http_request_context_t *http_context) {
    aws_mutex_lock(&http_context->connection_mutex);
    if (http_context->has_request) {
        iot_http_response_t *response = aws_mem_acquire(http_context->alloc, sizeof(iot_http_response_t));
        response->error_code = CODE_HTTP_REQUEST_REPETITION;
        if (http_context->callback != NULL) {
            http_context->callback(response, http_context->callback_user_data);
        }
        aws_mutex_unlock(&http_context->connection_mutex);
        return response;
        // 重复调用该方法, 返回错误
    }
    iot_http_response_t *response = _http_request_inner(http_context);
    aws_mutex_unlock(&http_context->connection_mutex);
    return response;
}


/**
 * 同步发起http 请求
 * @param http_context
 * @return
 */
iot_http_response_t *_http_request_inner(iot_http_request_context_t *http_context) {
    aws_http_library_init(http_context->alloc);
    http_context->has_request = true;
    _s_init_http_response(http_context);
    struct aws_uri *uri = (struct aws_uri *) aws_mem_acquire(http_context->alloc, sizeof(struct aws_uri));
    http_context->uri = uri;
    int error_code = CODE_SUCCESS;

    if (http_context->url == NULL || !aws_string_is_valid(http_context->url)) {
        error_code = CODE_HTTP_URL_INVALID;
        goto http_error;
    }

    // url 转 uri
    struct aws_byte_cursor url_cursor = aws_byte_cursor_from_string(http_context->url);
    struct aws_byte_cursor result = aws_byte_cursor_right_trim_pred(&url_cursor, url_trim);
    int ret = aws_uri_init_parse(uri, http_context->alloc, &result);
    if (ret != AWS_OP_SUCCESS) {
        error_code = CODE_HTTP_URL_PARSE_ERROR;
        goto http_error;
    }

    const struct aws_byte_cursor *host = aws_uri_host_name(uri);
    LOGD(IOT_TAG_HTTP, "iot_http_request url = %.*s", AWS_BYTE_CURSOR_PRI(result));

    http_context->core_ctx->tls_ctx_options.verify_peer = !use_local_proxy;
    aws_tls_connection_options_init_from_ctx(&http_context->tls_connection_options, http_context->core_ctx->tls_ctx);
    aws_tls_connection_options_set_server_name(&http_context->tls_connection_options, http_context->alloc, host);

    struct aws_http_client_connection_options http_options = AWS_HTTP_CLIENT_CONNECTION_OPTIONS_INIT;
    http_options.allocator = http_context->alloc;
    http_options.bootstrap = http_context->core_ctx->client_bootstrap;
    http_options.host_name = *host;

    // 判断是否是 http
    struct aws_byte_cursor prefix = aws_byte_cursor_from_c_str("https");
    if (aws_byte_cursor_starts_with(&url_cursor, &prefix)) {
        http_options.port = HTTPS_PORT;
    } else {
        http_options.port = HTTP_PORT;
    }
    http_options.on_setup = _s_on_connection_setup;// 连接建立成功的回调
    http_options.on_shutdown = _s_on_connection_shutdown;

    struct aws_socket_options socket_options = {
            .type = AWS_SOCKET_STREAM,
            .domain = AWS_SOCKET_IPV4,
            .connect_timeout_ms =http_context->connect_timeout_ms
    };
    http_options.socket_options = &socket_options;
    http_options.tls_options = &http_context->tls_connection_options;
    http_options.user_data = http_context;

    // 代理设置
    if (use_local_proxy) {
        struct aws_http_proxy_options proxy_options = {
                .host = aws_byte_cursor_from_c_str("127.0.0.1"),
                .port = 8888,
        };
        http_options.proxy_options = &proxy_options;
    }
    // 触发 http 连接
    ret = aws_http_client_connect(&http_options);
    if (ret != AWS_OP_SUCCESS) {
        error_code = CODE_HTTP_CLIENT_CONNECT_ERROR;
        goto http_error;
    }

    if (!http_context->is_asyn_request) {
        // 同步请求
        // 等待 connect 连接
        aws_condition_variable_wait_pred(&http_context->wait_connection_cvar, &http_context->connection_mutex, _s_waite_connect, http_context);
        if (http_context->wait_connection_result == 0 && http_context->client_connection != NULL) {
            // 连接建立成功, 开始发送数据
            _do_request(http_context);
            // 关闭链接
            aws_http_connection_close(http_context->client_connection);
        }
    }
    return http_context->response;

    http_error:
    http_context->response->error_code = error_code;
    return http_context->response;
}


/**
 * http respons 的分段流, 一次请求会回调多次改方法
 * @param stream
 * @param data
 * @param user_data
 * @return
 */
static int _s_on_stream_body(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void) stream;
    iot_http_request_context_t *http_ctx = user_data;
    aws_mutex_lock(&http_ctx->response_lock);
    int ret = AWS_OP_SUCCESS;
    // 外部自己处理每一次 respons 流, 主要是下载部分在使用
    if (http_ctx->on_response_body != NULL) {
        ret = http_ctx->on_response_body(stream, data, http_ctx);
    } else {
        LOGD(IOT_TAG_HTTP, "_s_on_stream_body size = %zu", data->len);
        // response 写入 buf 中
        http_ctx->response->body_size += data->len;
        http_ctx->response->response_body = data->ptr;
    }
    aws_mutex_unlock(&http_ctx->response_lock);
    return ret;
}

/**
 * respons 流读取完成
 * @param stream
 * @param error_code
 * @param user_data
 */
static void _s_on_stream_complete(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void) stream;
    iot_http_request_context_t *http_ctx = user_data;
    LOGD(IOT_TAG_HTTP, " _s_on_stream_complete error_code = %d ", error_code);

    if (http_ctx->on_complete != NULL) {
        http_ctx->on_complete(stream, error_code, user_data);
        aws_http_connection_close(http_ctx->client_connection);
        return;
    }

    int status_code;
    aws_http_stream_get_incoming_response_status(stream, &status_code);

    aws_mutex_lock(&http_ctx->response_lock);
    http_ctx->wait_connection_result = error_code;
    if (error_code == 0 && status_code != AWS_HTTP_STATUS_CODE_200_OK) { // not 200
        http_ctx->response->error_code = status_code;
    }
    // 打印 response
    LOGD(IOT_TAG_HTTP, "_s_on_stream_complete status_code = %d length = %d", status_code, strlen(http_ctx->response->response_body));
    // 数据量比较小的respons 打印到日志中
    if (error_code == 0 && http_ctx->response->body_size < 1000) {
        LOGD(IOT_TAG_HTTP, "_s_on_stream_complete response data str = %s", (http_ctx->response->response_body));
    }
    _call_back_response(http_ctx);
    http_ctx->stream_complete = true;
    aws_condition_variable_notify_one(&http_ctx->wait_response_cvar);
    aws_mutex_unlock(&http_ctx->response_lock);
}


/**
 * respons 的header 处理, 每个header 会回调一遍, 这里把它放入缓存中
 * @param stream
 * @param header_block
 * @param header_array
 * @param num_headers
 * @param user_data
 * @return
 */
static int _s_on_incoming_headers_fn(
        struct aws_http_stream *stream,
        enum aws_http_header_block header_block,
        const struct aws_http_header *header_array,
        size_t num_headers,
        void *user_data) {
    iot_http_request_context_t *http_ctx = user_data;
    aws_mutex_lock(&http_ctx->response_lock);

    aws_mutex_unlock(&http_ctx->response_lock);

    if (http_ctx->on_get_header != NULL) {
        http_ctx->on_get_header(header_array, num_headers, user_data);
    }

    return AWS_OP_SUCCESS;
}


static bool waite_response(void *context) {
    iot_http_request_context_t *http_context = (iot_http_request_context_t *) context;
    return http_context->stream_complete;
}

// 发起正在的请求
void _do_request(iot_http_request_context_t *http_context) {
    struct aws_http_message *http_message = aws_http_message_new_request(http_context->alloc);
    http_context->http_request_message = http_message;

    aws_http_message_set_request_path(http_message, *aws_uri_path_and_query(http_context->uri));

    struct aws_http_header header_host = {
            .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(HTTPS_HEADER_KEY_HOST),
            .value = *aws_uri_host_name(http_context->uri),
    };
    aws_http_message_add_header(http_message, header_host);

    if (http_context->headers != NULL) {
        int custom_header_count = aws_http_headers_count(http_context->headers);
        for (int i = 0; i < custom_header_count; i++) {
            struct aws_http_header out_header;
            aws_http_headers_get_index(http_context->headers, i, &out_header);
            aws_http_message_add_header(http_message, out_header);
        }
    }

    if (http_context->method == HEADER) {
        aws_http_message_set_request_method(http_message, aws_http_method_head);
    } else if (http_context->method == POST) {
        http_context->body_cur = aws_byte_cursor_from_string(http_context->json_body);
        http_context->post_body_stream = aws_input_stream_new_from_cursor(http_context->alloc,
                                                                          &http_context->body_cur);
        aws_http_message_set_body_stream(http_message, http_context->post_body_stream);
        // 计算 post 请求的body 的长度
        // 当前仅支持 application/json 类型的请求
        char content_length_buffer[30];
        sprintf(content_length_buffer, "%zu", http_context->json_body->len);
        LOGD(IOT_TAG_HTTP, "_do_request body content_length = %s", content_length_buffer);
        struct aws_http_header headers[] = {
                {
                        // Post 请求要带上body 必须指定 Content-Length
                        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(HTTPS_HEADER_KEY_CONTENT_LENGTH),
                        .value = aws_byte_cursor_from_c_str(content_length_buffer),
                },
                {
                        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(HTTPS_HEADER_KEY_CONTENT_TYPE),
                        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(HTTPS_HEADER_KEY_CONTENT_TYPE_JSON),
                }
        };
        aws_http_message_add_header_array(http_message, headers, AWS_ARRAY_SIZE(headers));
        aws_http_message_set_request_method(http_message, aws_http_method_post);
    } else {
        aws_http_message_set_request_method(http_message, aws_http_method_get);
    }

    // 初始化 respons body
    http_context->response->response_body = aws_mem_acquire( http_context->alloc, 4096);
    struct aws_http_make_request_options req_options = {
            .self_size = sizeof(req_options),
            .request = http_message,
            .on_response_body = _s_on_stream_body,
            .on_complete = _s_on_stream_complete,
            .on_response_headers = _s_on_incoming_headers_fn,
            .user_data = http_context,
    };
    // 发送请求
    http_context->stream = aws_http_connection_make_request(http_context->client_connection, &req_options);
    if (http_context->stream != NULL) {
        aws_http_stream_activate(http_context->stream);
        if (!http_context->is_asyn_request) {
            // 同步等待结果
            aws_condition_variable_wait_pred(&http_context->wait_response_cvar, &http_context->response_lock, waite_response,
                                             http_context);
        }
    } else {
        // 请求失败
        http_context->response->error_code = CODE_HTTP_REQUEST_STREAM_NULL;
        _call_back_response(http_context);
    }
}

void _call_back_response(iot_http_request_context_t *ctx) {
    if (ctx->callback != NULL) {
        ctx->callback(ctx->response, ctx->callback_user_data);
    }
    if (ctx->is_asyn_request && ctx->client_connection != NULL) {
        aws_http_connection_close(ctx->client_connection);
    }
}

void iot_clean_http(iot_http_request_context_t *http_ctx) {
    LOGD(IOT_TAG_HTTP, "iot_clean_http called");
    if (http_ctx->client_connection != NULL) {
        aws_http_connection_close(http_ctx->client_connection);
        aws_http_connection_release(http_ctx->client_connection);
        http_ctx->client_connection = NULL;
    }

    if (http_ctx->http_request_message != NULL) {
        aws_http_message_destroy(http_ctx->http_request_message);
        http_ctx->http_request_message = NULL;
    }
    if (http_ctx->stream != NULL) {
        aws_http_stream_release(http_ctx->stream);
        http_ctx->stream = NULL;
    }
    aws_tls_connection_options_clean_up(&http_ctx->tls_connection_options);

    aws_mutex_clean_up(&http_ctx->data_mutex);
    aws_mutex_clean_up(&http_ctx->connection_mutex);
    aws_mutex_clean_up(&http_ctx->response_lock);

    aws_condition_variable_clean_up(&http_ctx->wait_connection_cvar);
    aws_condition_variable_clean_up(&http_ctx->wait_response_cvar);

    if (http_ctx->uri != NULL) {
        aws_uri_clean_up(http_ctx->uri);
        aws_mem_release(http_ctx->alloc, http_ctx->uri);
        http_ctx->uri = NULL;
    }

    if (http_ctx->url != NULL) {
        aws_string_destroy_secure(http_ctx->url);
        http_ctx->url = NULL;
    }

    if (http_ctx->json_body != NULL) {
        aws_string_destroy_secure(http_ctx->json_body);
        http_ctx->json_body = NULL;
    }

    if (http_ctx->headers != NULL) {
        aws_http_headers_release(http_ctx->headers);
        http_ctx->headers = NULL;
    }

    if (http_ctx->post_body_stream != NULL) {
        aws_input_stream_destroy(http_ctx->post_body_stream);
        http_ctx->post_body_stream = NULL;
    }

    if (http_ctx->is_asyn_request) {
        iot_http_response_release(http_ctx->response);
    }

}

void _s_init_http_response(iot_http_request_context_t *http_context) {
    http_context->response = aws_mem_acquire(http_context->alloc, sizeof(iot_http_response_t));
//    http_context->response->current_info_headers = aws_http_headers_new(http_context->alloc);
}

void iot_http_response_release(iot_http_response_t *response) {
    if (response != NULL) {
        aws_mem_release(get_iot_core_context()->alloc, response);
    }
}