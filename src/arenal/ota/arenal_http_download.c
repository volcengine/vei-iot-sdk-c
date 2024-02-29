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
#include <aws/common/file.h>
#include "arenal_http_download.h"
#include "core/iot_log.h"
#include "core/iot_core.h"
#include "core/iot_util.h"
#include "core/iot_core_header.h"
#include "iot_ota_header.h"
#include <aws/common/mutex.h>


void s_http_download_header_callback(struct iot_http_response *response, void *user_data);

void _http_download_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data);

int _http_download_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data);


iot_http_download_handler_t *new_http_download_handler() {
    iot_http_download_handler_t *download_handler = aws_mem_calloc(get_iot_core_context()->alloc, 1, sizeof(iot_http_download_handler_t));
    download_handler->allocator = get_iot_core_context()->alloc;
    aws_mutex_init(&download_handler->write_file_lock);
    download_handler->download_response = aws_mem_calloc(get_iot_core_context()->alloc, 1, sizeof(struct http_download_file_response));
    return download_handler;
}

void http_download_handler_set_url(iot_http_download_handler_t *handler, const char *url) {
    handler->url = aws_string_new_from_c_str(handler->allocator, url);
}

void http_download_handler_set_file_download_path(iot_http_download_handler_t *handler, const char *path) {
    handler->download_file_path = aws_string_new_from_c_str(handler->allocator, path);
}

void http_download_handler_set_file_download_dir(iot_http_download_handler_t *handler, const char *path) {
    handler->download_dir = aws_string_new_from_c_str(handler->allocator, path);
}

void http_download_handler_set_download_callback(iot_http_download_handler_t *handler, http_download_callback *download_callback, void *user_data) {
    handler->download_callback = download_callback;
    handler->download_callback_user_data = user_data;

}

void http_download_handler_set_rev_data_callback(iot_http_download_handler_t *handler, http_download_rev_data_callback *download_callback, void *user_data) {
    handler->download_rev_data_callback = download_callback;
    handler->download_rev_data_callback_user_data = user_data;

}

void http_download_response_release(struct http_download_file_response *response) {
    if (response == NULL) {
        return;
    }
    if (response->down_file) {
        aws_string_destroy_secure(response->down_file);
    }
}

void http_download_handler_release(iot_http_download_handler_t *handler) {
    if (handler->url != NULL) {
        aws_string_destroy_secure(handler->url);
    }

    if (handler->download_response != NULL) {
        if (handler->download_response->down_file) {
            aws_string_destroy_secure(handler->download_response->down_file);
        }
        aws_mem_release(handler->allocator, handler->download_response);
    }
    aws_mem_release(handler->allocator, handler);
}


static void _s_on_get_header_fn(
        const struct aws_http_header *header_array,
        size_t num_headers,
        void *user_data) {
    iot_http_request_context_t *http_ctx = user_data;
    iot_http_download_handler_t *http_download_ctx = http_ctx->user_data;

    for (int i = 0; i < num_headers; i++) {
        // 通过header 获取大小
        struct aws_http_header header = header_array[i];
        struct aws_byte_cursor cl_cur = aws_byte_cursor_from_c_str("Content-Length");
        if (aws_byte_cursor_eq_ignore_case(&header.name, &cl_cur)) {
            char *content_length_str = aws_cur_to_char_str(http_ctx->alloc, &header.value);
            http_download_ctx->download_file_size = atol(content_length_str);
        }
    }
}


int http_download_start(iot_http_download_handler_t *download_handler) {
    struct iot_http_request_context *get_data_ctx = iot_new_http_ctx(download_handler->allocator);
    iot_http_ctx_set_url(get_data_ctx, aws_string_c_str(download_handler->url));
    iot_http_ctx_set_user_data(get_data_ctx, download_handler);
    _http_ctx_set_on_complete(get_data_ctx, _http_download_on_stream_complete_fn);
    _http_ctx_set_on_response_body(get_data_ctx, _http_download_on_incoming_body_fn);
    _http_ctx_set_on_get_header(get_data_ctx, _s_on_get_header_fn);
    download_handler->download_data_handler = get_data_ctx;
    return iot_http_request_asyn(download_handler->download_data_handler, NULL, download_handler);

}

void _http_download_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct iot_http_request_context *get_data_ctx = user_data;
    iot_http_download_handler_t *http_download_ctx = get_data_ctx->user_data;

    if (http_download_ctx->down_file != NULL) {
        fclose(http_download_ctx->down_file);
    }
    if (error_code != 0) {
        // 删除下载文件
        http_download_ctx->download_response->error_code = error_code;
        aws_file_delete(http_download_ctx->download_file_path);
        http_download_ctx->download_response->download_failed = true;
    }
    _callback_download_response(http_download_ctx);

}


/**
 * 接收 下载的数据, 会回调多次
 * @param stream
 * @param data
 * @param user_data
 * @return
 */
int _http_download_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    struct iot_http_request_context *get_data_ctx = user_data;
    iot_http_download_handler_t *http_download_ctx = get_data_ctx->user_data;
    return _write_down_file(http_download_ctx, data);
}


void _callback_download_response(iot_http_download_handler_t *download_handler) {
    if (download_handler->download_callback != NULL && !download_handler->has_called_callback) {
        download_handler->has_called_callback = true;
        download_handler->download_callback(download_handler, download_handler->download_response, download_handler->download_callback_user_data);
    }
    http_download_handler_release(download_handler);
}


int _write_down_file(iot_http_download_handler_t *download_handler, const struct aws_byte_cursor *data) {
    if (download_handler->download_response->download_failed) {
        // 前面已经下载失败了, 不处理
        return HTTP_DOWNLOAD_DOWNLOAD_BEFORE_FAILED;
    }

    if (download_handler->download_file_size <= 0) {
        return HTTP_DOWNLOAD_DOWNLOAD_UNKNOWN_FILE_SIZE;
    }

    if (download_handler->download_file_path == NULL && download_handler->download_dir == NULL) {
        LOGD(IOT_TAG_HTTP, "下载失败 下载路径为空 ");
        download_handler->download_response->download_failed = true;
        download_handler->download_response->error_code = HTTP_DOWNLOAD_DOWNLOAD_DIR_OR_PATH_NULL;
        _callback_download_response(download_handler);
        return HTTP_DOWNLOAD_DOWNLOAD_DIR_OR_PATH_NULL;
    }
    if (download_handler->down_file == NULL) {
        if (download_handler->download_file_path != NULL) {
            // 设置了具体的下载路径
            if (aws_path_exists(download_handler->download_file_path)) {
                aws_file_delete(download_handler->download_file_path);
            }
            download_handler->down_file = aws_fopen(aws_string_c_str(download_handler->download_file_path), "a+");
        } else {
            const struct aws_byte_cursor *path_cur = aws_uri_path(download_handler->download_data_handler->uri);

            // 通过url 获取文件名
            struct aws_array_list topic_split_data_list;
            aws_array_list_init_dynamic(&topic_split_data_list, download_handler->allocator, 8, sizeof(struct aws_byte_cursor));
            aws_byte_cursor_split_on_char(path_cur, '/', &topic_split_data_list);
            int length = aws_array_list_length(&topic_split_data_list);
            struct aws_byte_cursor file_name_cur = {0};
            aws_array_list_get_at(&topic_split_data_list, &file_name_cur, length - 1);
            LOGD(IOT_TAG_HTTP, "_write_down_file url path seg length = length = %d, filename = %.*s", length, AWS_BYTE_CURSOR_PRI(file_name_cur));

            char filename_array[1024];
            AWS_ZERO_ARRAY(filename_array);
            struct aws_byte_buf filename_buf = aws_byte_buf_from_empty_array(filename_array, sizeof(filename_array));
            aws_byte_buf_write_from_whole_cursor(&filename_buf, aws_byte_cursor_from_string(download_handler->download_dir));
            aws_byte_buf_write_from_whole_cursor(&filename_buf, aws_byte_cursor_from_c_str(AWS_PATH_DELIM_STR));
            // 创建目录
            if (!aws_directory_exists(download_handler->download_dir)) {
                int ret = aws_directory_create(download_handler->download_dir);
                if (ret != AWS_OP_SUCCESS) {
                    // 创建目录失败
                    download_handler->download_response->download_failed = true;
                    download_handler->download_response->error_code = HTTP_DOWNLOAD_DIR_CREAT_ERROR;
                    return HTTP_DOWNLOAD_DIR_CREAT_ERROR;
                }
            }
            aws_byte_buf_write_from_whole_cursor(&filename_buf, file_name_cur);
            download_handler->download_file_path = aws_string_new_from_array(download_handler->allocator, filename_buf.buffer, filename_buf.len);
            if (aws_path_exists(download_handler->download_file_path)) {
                aws_file_delete(download_handler->download_file_path);
            }
            download_handler->down_file = aws_fopen(aws_string_c_str(download_handler->download_file_path), "a+");
            aws_array_list_clean_up(&topic_split_data_list);
        }
        download_handler->download_response->down_file = aws_string_c_str(download_handler->download_file_path);

    }
    if (download_handler->down_file == NULL) {
        // 文件创建失败
        LOGD(IOT_TAG_HTTP, "_write_down_file 文件创建失败 ");
        download_handler->download_response->download_failed = true;
        return HTTP_DOWNLOAD_FILE_CREAT_ERROR;
    }

    download_handler->download_response->file_size += data->len;
    aws_mutex_try_lock(&download_handler->write_file_lock);
    size_t result = fwrite(data->ptr, 1, data->len, download_handler->down_file);
    aws_mutex_unlock(&download_handler->write_file_lock);

    if (download_handler->download_rev_data_callback != NULL) {
        double percent = 100 * download_handler->download_response->file_size / download_handler->download_file_size;
        download_handler->download_rev_data_callback(download_handler, data->ptr, data->len, (int) percent, download_handler->download_rev_data_callback_user_data);
    }

    if (result < data->len) {
        download_handler->download_response->download_failed = true;
        download_handler->download_response->error_code = HTTP_DOWNLOAD_FILE_WRITE_ERROR;
        LOGD(IOT_TAG_HTTP, "_write_down_file 下载失败 写入文件失败");
        _callback_download_response(download_handler);
        return HTTP_DOWNLOAD_FILE_WRITE_ERROR;
    }

    fflush(download_handler->down_file);
    return AWS_OP_SUCCESS;
}

void close_download(iot_http_download_handler_t *download_ctx) {
    if (download_ctx->header_request_handler != NULL && download_ctx->header_request_handler->client_connection_is_shutdown) {
        aws_http_connection_close(download_ctx->header_request_handler->client_connection);
    }
    if (download_ctx->download_data_handler != NULL && download_ctx->download_data_handler->client_connection_is_shutdown) {
        aws_http_connection_close(download_ctx->download_data_handler->client_connection);
    }
}
