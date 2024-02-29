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

#ifndef ARENAL_IOT_ARENAL_HTTP_DOWNLOA_H
#define ARENAL_IOT_ARENAL_HTTP_DOWNLOA_H

#include <stddef.h>
#include <stdbool.h>
#include "../core/iot_http.h"

#define TAG_HTTP_DOWNLOAD "http_download"


struct http_download_file_response {
    const char *down_file;
    size_t file_size;
    bool download_failed;
    int error_code;
    int http_inner_code;
};

typedef struct iot_http_download_handler iot_http_download_handler_t;


typedef void (http_download_callback)(void *download_handler, struct http_download_file_response *ctx, void *user_data);

typedef void (http_download_rev_data_callback)(void *download_handler, uint8_t *data_prt, size_t len, int32_t percent, void *user_data);

iot_http_download_handler_t *new_http_download_handler();

void http_download_handler_set_url(iot_http_download_handler_t *handler, const char *url);

void http_download_handler_set_file_download_path(iot_http_download_handler_t *handler, const char *path);

void http_download_handler_set_file_download_dir(iot_http_download_handler_t *handler, const char *path);

void http_download_handler_set_download_callback(iot_http_download_handler_t *handler, http_download_callback *download_callback, void *user_data);

void http_download_handler_set_rev_data_callback(iot_http_download_handler_t *handler, http_download_rev_data_callback *download_callback, void *user_data);

int http_download_start(iot_http_download_handler_t *download_handler);

void close_download(iot_http_download_handler_t *download_ctx);

void http_download_handler_release(iot_http_download_handler_t *handler);

#endif //ARENAL_IOT_ARENAL_HTTP_DOWNLOA_H