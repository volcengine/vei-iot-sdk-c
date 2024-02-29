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

#ifndef ARENAL_IOT_IOT_HTTP_H
#define ARENAL_IOT_IOT_HTTP_H

#define IOT_TAG_HTTP "iot_http"

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define HTTPS_HEADER_KEY_CONTENT_LENGTH "Content-Length"
#define HTTPS_HEADER_KEY_CONTENT_TYPE "Content-Type"
#define HTTPS_HEADER_KEY_CONTENT_TYPE_JSON "application/json"
#define HTTPS_HEADER_KEY_HOST "Host"

#define HTTPS_DEFAULT_CONNECTION_TIME_OUT 10 * 1000

enum iot_http_method {
    GET,
    POST,
    HEADER,
};

/**
 * http 请求 response
 */
typedef struct iot_http_response {
    size_t body_size;
    char* response_body;
    int32_t error_code;
    int32_t inner_error_code; // aws lib 返回的错误吗
//    struct aws_http_headers *current_info_headers;
} iot_http_response_t;

/**
 * 异步请求回调
 */
typedef void (iot_http_request_asyn_callback)(iot_http_response_t *ctx, void *user_data);


/**
 * 请求 handler 一个请求一个 通过 iot_new_http_ctx 创建
 */
typedef struct iot_http_request_context iot_http_request_context_t;


iot_http_request_context_t *iot_new_http_ctx();

void iot_http_ctx_release(iot_http_request_context_t *ctx);

void iot_http_ctx_set_url(iot_http_request_context_t *ctx, char *url);

void iot_http_ctx_add_header(iot_http_request_context_t *ctx, char *key, char *value);

void iot_http_ctx_set_method(iot_http_request_context_t *ctx, enum iot_http_method method);

void iot_http_ctx_set_json_body(iot_http_request_context_t *ctx, char *json_body);

void iot_http_ctx_set_user_data(iot_http_request_context_t *ctx, void *user_data);

void iot_http_ctx_set_connect_time_out_mil(iot_http_request_context_t *ctx, int32_t time_mil);

/**
 * 同步请求
 * @param http_context
 * @return
 */
struct iot_http_response *iot_http_request(iot_http_request_context_t *http_context);

void iot_http_response_release(struct iot_http_response *response);

void iot_clean_http(iot_http_request_context_t *http_ctx);

/**
 * 异步请求
 * @param http_context
 * @param callback
 * @param userdata
 * @return
 */
int iot_http_request_asyn(iot_http_request_context_t *http_context, iot_http_request_asyn_callback *callback, void *userdata);



#endif //ARENAL_IOT_IOT_HTTP_H
