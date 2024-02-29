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
#include <aws/common/json.h>
#include <thing_model/iot_tm_header.h>
#include <aws/common/file.h>
#include <core/iot_kv.h>
#include "iot_ota_api.h"
#include "iot_ota_header.h"


#define OTA_UPGRADE_NOTIFY_TOPIC "sys/%s/%s/ota/notify/+"
#define OTA_REQUEST_UPGRADE_REPLY_TOPIC "sys/%s/%s/ota/upgrade/post_reply"
#define OTA_UPGRADE_PROGRESS_REPORT_TOPIC "sys/%s/%s/ota/progress/%s"
#define OTA_REQUEST_UPGRADE_TOPIC "sys/%s/%s/ota/upgrade/post"
#define OTA_VERSION_REPORT_TOPIC "sys/%s/%s/ota/version"

#define KEY_SAVE_JOB_INFO "key_save_job_info_%s"
#define KEY_SAVE_TASK_INFO "key_save_task_info_%s"

iot_ota_handler_t *iot_ota_init() {
    iot_ota_handler_t *ota_handler = aws_mem_calloc(get_iot_core_context()->alloc, 1, sizeof(iot_ota_handler_t));
    ota_handler->allocator = get_iot_core_context()->alloc;
    aws_mutex_init(&ota_handler->lock);
    ota_handler->kv_ctx = iot_kv_init("", "ota.kv");
    aws_hash_table_init(&ota_handler->task_hash_map, ota_handler->allocator, 2, aws_hash_c_string, aws_hash_callback_c_str_eq, NULL, NULL);
    // 任务Task Map jobid -> jobTask
    ota_handler->auto_request_ota_info_interval_sec = OTA_AUTO_REQUEST_INFO_INTERVAL_SEC;

    return ota_handler;
}

void iot_ota_deinit(iot_ota_handler_t *handler) {
    aws_mutex_clean_up(&handler->lock);
    iot_kv_deinit(handler->kv_ctx);
    aws_mem_release(handler->allocator, handler->device_info_array);
    aws_string_destroy_secure(handler->download_dir);
    aws_hash_table_clean_up(&handler->task_hash_map);
}


int32_t iot_ota_set_get_job_info_callback(iot_ota_handler_t *handle, iot_ota_get_job_info_callback *callback, void *user_data) {
    if (handle == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    handle->get_jon_info_callback = callback;
    handle->get_jon_info_callback_user_data = user_data;
    return CODE_SUCCESS;
}


int32_t iot_ota_set_download_complete_callback(iot_ota_handler_t *handle, iot_ota_download_complete_callback *callback, void *user_data) {
    if (handle == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    handle->ota_download_complete_callback = callback;
    handle->ota_download_complete_callback_user_data = user_data;
    return CODE_SUCCESS;
}

int32_t iot_ota_set_rev_data_progress_callback(iot_ota_handler_t *handle, iot_ota_rev_data_progress_callback *callback, void *user_data) {
    if (handle == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    handle->iot_ota_rev_data_progress_callback = callback;
    handle->iot_ota_rev_data_progress_callback_user_data = user_data;
    return CODE_SUCCESS;
}

int32_t iot_ota_set_auto_request_ota_info_interval_sec(iot_ota_handler_t *handle, int32_t interval) {
    handle->auto_request_ota_info_interval_sec = interval;
}

int32_t iot_ota_set_download_dir(iot_ota_handler_t *handle, const char *download_dir) {
    if (handle == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    handle->download_dir = aws_string_new_from_c_str(handle->allocator, download_dir);
    return CODE_SUCCESS;
}


int32_t iot_ota_set_mqtt_handler(iot_ota_handler_t *handle, iot_mqtt_ctx_t *mqtt_handle) {
    if (handle == NULL || mqtt_handle == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }

    handle->mqtt_handle = mqtt_handle;
    _mqtt_sub_ota_info(handle);
    _mqtt_sub_ota_upgrade_post_reply(handle);
    return CODE_SUCCESS;
}

int32_t iot_ota_set_device_module_info(iot_ota_handler_t *handler, iot_ota_device_info_t *device_info_array, int device_info_array_size) {
    handler->device_info_array_size = device_info_array_size;
    if (handler->device_info_array != NULL) {
        aws_mem_release(handler->allocator, handler->device_info_array);
    }
    handler->device_info_array = aws_mem_calloc(handler->allocator, device_info_array_size, sizeof(iot_ota_device_info_t));
    memcpy(handler->device_info_array, device_info_array, device_info_array_size * sizeof(iot_ota_device_info_t));


    for (int i = 0; i < handler->device_info_array_size; i++) {
        iot_ota_device_info_t deviceInfo = handler->device_info_array[i];

        char kv_key_job_info[100];
        sprintf(kv_key_job_info, KEY_SAVE_JOB_INFO, deviceInfo.module);


        struct aws_byte_cursor key_cur = aws_byte_cursor_from_c_str(kv_key_job_info);
        struct aws_byte_cursor value = {0};
        iot_get_kv_string(handler->kv_ctx, key_cur, &value);
        if (value.len > 0) {


            struct aws_json_value *data = aws_json_value_new_from_string(handler->allocator, value);
            iot_ota_job_info_t *jobInfo = _ota_data_json_to_ota_job_info(handler->allocator, data);

            char kv_key_task_info[100];
            sprintf(kv_key_task_info, KEY_SAVE_TASK_INFO, jobInfo->ota_job_id);
            struct aws_byte_cursor key_task_info_cur = aws_byte_cursor_from_c_str(kv_key_task_info);
            struct aws_byte_cursor task_info_value = {0};
            iot_get_kv_string(handler->kv_ctx, key_task_info_cur, &task_info_value);

            struct aws_byte_cursor current_version_cur = aws_byte_cursor_from_c_str(deviceInfo.version);
            struct aws_byte_cursor dest_version_cur = aws_byte_cursor_from_c_str(jobInfo->dest_version);
            if (aws_byte_cursor_eq_ignore_case(&current_version_cur, &dest_version_cur)) {
                // 上报安装完成了
                iot_ota_report_progress_success(handler, jobInfo->ota_job_id, UpgradeDeviceStatusSuccess);
                iot_remove_key_str(handler->kv_ctx, kv_key_job_info);
                iot_remove_key_str(handler->kv_ctx, kv_key_task_info);
            } else {
                if (task_info_value.len > 0) {
                    // 缓存task info
                    struct aws_json_value *task_json = aws_json_value_new_from_string(handler->allocator, task_info_value);
                    iot_ota_job_task_info_t *task_info = aws_mem_calloc(handler->allocator, 1, sizeof(iot_ota_job_task_info_t));
                    task_info->ota_handler = handler;
                    task_info->server_job_info = jobInfo;
                    task_info->decode_url = aws_json_get_string1_val(handler->allocator, task_json, "decode_url");
                    task_info->retry_time = (int32_t) aws_json_get_num_val(task_json, "retry_time");
                    task_info->is_pending_to_retry = true;
                    task_info->upgrade_device_status = (int) aws_json_get_num_val(task_json, "upgrade_device_status");
                    task_info->ota_file_path = aws_json_get_str(handler->allocator, task_json, "ota_file_path");
                    // 写入map
                    aws_hash_table_put(&handler->task_hash_map, jobInfo->ota_job_id, task_info, NULL);
                }
            }

        }
    }

    // 读取历史 task 写入缓存.
    // 上报 版本号
    iot_ota_report_version(handler, device_info_array, device_info_array_size);
}

void job_info_release(iot_ota_handler_t *handler, iot_ota_job_info_t *job_info) {
    if (job_info->ota_job_id != NULL) {
        aws_mem_release(handler->allocator, job_info->ota_job_id);
        job_info->ota_job_id = NULL;
    }
    if (job_info->dest_version != NULL) {
        aws_mem_release(handler->allocator, job_info->dest_version);
        job_info->dest_version = NULL;
    }
    if (job_info->url != NULL) {
        aws_mem_release(handler->allocator, job_info->url);
        job_info->url = NULL;
    }
    if (job_info->module != NULL) {
        aws_mem_release(handler->allocator, job_info->module);
        job_info->module = NULL;
    }
    if (job_info->sign != NULL) {
        aws_mem_release(handler->allocator, job_info->sign);
        job_info->sign = NULL;
    }
    aws_mem_release(handler->allocator, job_info);
}

void ota_task_release(iot_ota_job_task_info_t *task_info) {
//    if (task_info->server_jon_info != NULL) {
//        job_info_release(task_info->ota_handler, task_info->server_jon_info);
//    }

    if (task_info->decode_url != NULL) {
        aws_string_destroy_secure(task_info->decode_url);
        task_info->decode_url = NULL;
    }
    // download_handler 在下载完成后会自动回收
    aws_mem_release(task_info->ota_handler->allocator, task_info);
}


static void s_ota_retry_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    iot_ota_job_task_info_t *ota_task = arg;
    struct aws_allocator *allocator = ota_task->ota_handler->allocator;
    iot_ota_start_download(ota_task->ota_handler, ota_task->server_job_info);
    aws_mem_release(allocator, task);
}

static void s_download_call_back(void *download_handler, struct http_download_file_response *response, void *user_data) {
    iot_ota_job_task_info_t *ota_task = user_data;
    LOGD(TAG_OTA, "s_download_call_back response code = %d file_size = %d", response->error_code, response->file_size);

    int ret = response->error_code;
    if (response->error_code == CODE_SUCCESS) {
        if (response->file_size != ota_task->server_job_info->size) {
            ret = OTA_DOWNLOAD_FILE_SIZE_ERROR;
            goto result_handler;
        }

        if (response->down_file == NULL || !aws_path_exists(response->down_file)) {
            ret = OTA_DOWNLOAD_FILE_EMPTY_ERROR;
            goto result_handler;
        }

        if (ota_task->server_job_info->sign != NULL && strlen(ota_task->server_job_info->sign) > 0) {
            FILE *fp = aws_fopen(aws_string_c_str(response->down_file), "rb");
            struct aws_string *md5_str = md5File(fp);
            bool is_sign_eq = aws_string_eq_c_str(md5_str, ota_task->server_job_info->sign);
            fclose(fp);
            aws_string_destroy_secure(md5_str);
            if (md5_str == NULL || !is_sign_eq) {
                ret = OTA_DOWNLOAD_FILE_SIGN_CHECK_ERROR;
                goto result_handler;
            }
        }
    }

    result_handler:
    if (ret != CODE_SUCCESS) {
        if (ota_task->ota_handler->ota_download_complete_callback != NULL) {
            ota_task->ota_handler->ota_download_complete_callback(ota_task->ota_handler,
                                                                  ret,
                                                                  ota_task->server_job_info,
                                                                  NULL,
                                                                  ota_task->ota_handler->ota_download_complete_callback_user_data);

        }
        // 上报下载失败
        iot_ota_report_progress_failed(ota_task->ota_handler, ota_task->server_job_info->ota_job_id, UpgradeDeviceStatusFailed, ret, "download failed");
        // delay 重试

        if (ota_task->retry_time < 3) {
            // 延迟重试
            ota_task->is_pending_to_retry = true;
            struct aws_task *retry_task = aws_mem_acquire(ota_task->ota_handler->allocator, sizeof(struct aws_task));
            aws_task_init(retry_task, s_ota_retry_task, ota_task, "retry_ota_task");
            LOGD(TAG_OTA, "s_download_call_back iot_core_post_delay_task");
            iot_core_post_delay_task(retry_task, OTA_RETRY_INTERVAL_SEC);
            iot_ota_save_job_task_info(ota_task);
        } else {
            // 删除 map 中的记录
            LOGD(TAG_OTA, "s_download_call_back 彻底失败");
            iot_ota_delete_job_task_info(ota_task);
            aws_hash_table_remove(&ota_task->ota_handler->task_hash_map, ota_task->server_job_info->ota_job_id, NULL, NULL);
            job_info_release(ota_task->ota_handler, ota_task->server_job_info);
            ota_task_release(ota_task);
        }

    } else {
        // 上报下载成功
        iot_ota_report_progress_success(ota_task->ota_handler, ota_task->server_job_info->ota_job_id, UpgradeDeviceStatusDownloaded);
        iot_ota_save_job_task_info(ota_task);
        if (ota_task->ota_handler->ota_download_complete_callback != NULL) {
            ota_task->ota_handler->ota_download_complete_callback(ota_task->ota_handler,
                                                                  response->error_code,
                                                                  ota_task->server_job_info,
                                                                  aws_string_c_str(response->down_file),
                                                                  ota_task->ota_handler->ota_download_complete_callback_user_data);
        }

    }

}

static void s_download_rev_data_callback(void *download_handler, uint8_t *data_prt, size_t len, int32_t percent, void *user_data) {
    iot_ota_job_task_info_t *ota_task = user_data;
    if (ota_task->ota_handler->ota_download_complete_callback != NULL) {
        ota_task->ota_handler->iot_ota_rev_data_progress_callback(ota_task->ota_handler,
                                                                  ota_task->server_job_info,
                                                                  data_prt, len, percent,
                                                                  ota_task->ota_handler->iot_ota_rev_data_progress_callback_user_data);
    }
}

void iot_ota_start_download(iot_ota_handler_t *handle, iot_ota_job_info_t *job_info) {
    // 判断是否有正在进行的任务?
    struct aws_hash_element *value_elem = NULL;
    aws_hash_table_find(&handle->task_hash_map, job_info->ota_job_id, &value_elem);
    iot_ota_job_task_info_t *last_task = NULL;
    if (value_elem != NULL) {
        last_task = (iot_ota_job_task_info_t *) value_elem->value;
        if (last_task->ota_file_path != NULL) {
            struct aws_string *ota_file_path_string = aws_string_new_from_c_str(handle->allocator, last_task->ota_file_path);
            if (last_task->server_job_info->sign != NULL && strlen(last_task->server_job_info->sign) > 0 && aws_path_exists(ota_file_path_string)) {
                aws_string_destroy_secure(ota_file_path_string);
                FILE *fp = aws_fopen(last_task->ota_file_path, "rb");
                struct aws_string *md5_str = md5File(fp);
                fclose(fp);
                bool is_sign_eq = aws_string_eq_c_str(md5_str, last_task->server_job_info->sign);
                aws_string_destroy_secure(md5_str);
                if (md5_str != NULL && is_sign_eq) {
                    // 之前的任务下载完了, 且文件校验成功 直接回调下载完成
                    if (handle->ota_download_complete_callback != NULL) {
                        handle->ota_download_complete_callback(handle, 0, job_info, last_task->ota_file_path, handle->ota_download_complete_callback_user_data);
                        return;
                    }
                }
            }

            if (!last_task->is_pending_to_retry) {
                // 任务正在进行
                return;
            }
        }
    }

    if (job_info->url == NULL || job_info->size <= 0) {
        return;
    }

    // 读取是否存在历史 task 是否下载完成, 文件签名校验是否通过, 如果通过的话, 无需再次下载.

    //  创建新的task
    iot_ota_job_task_info_t *ota_task = aws_mem_calloc(handle->allocator, 1, sizeof(iot_ota_job_task_info_t));
    ota_task->ota_handler = handle;
    ota_task->server_job_info = job_info;
    ota_task->retry_time = 0;
    ota_task->is_pending_to_retry = false;
    if (last_task != NULL) {
        // 销毁上一个task
        ota_task->retry_time = last_task->retry_time + 1;
    } else {
        ota_task->retry_time = 0;
    }

    // url 解密
    ota_task->decode_url = aes_decode(handle->allocator, aws_string_c_str(handle->mqtt_handle->device_secret), job_info->url);

    // 开始下载
    iot_http_download_handler_t *download_handler = new_http_download_handler();
    ota_task->download_handler = download_handler;
    http_download_handler_set_url(download_handler, aws_string_c_str(ota_task->decode_url));
    if (handle->download_dir != NULL) {
        http_download_handler_set_file_download_dir(download_handler, aws_string_c_str(handle->download_dir));
    } else {
        http_download_handler_set_file_download_dir(download_handler, "download");
    }

    http_download_handler_set_download_callback(download_handler, s_download_call_back, ota_task);
    http_download_handler_set_rev_data_callback(download_handler, s_download_rev_data_callback, ota_task);
    http_download_start(download_handler);
    ota_task->upgrade_device_status = UpgradeDeviceStatusDownloading;

    // 上报下载中
    iot_ota_report_progress_success(handle, job_info->ota_job_id, UpgradeDeviceStatusDownloading);

    aws_hash_table_put(&handle->task_hash_map, job_info->ota_job_id, ota_task, NULL);
    if (last_task != NULL) {
        // 销毁上一个task
        ota_task_release(last_task);
    }

}

void _mqtt_sub_ota_info(iot_ota_handler_t *ota_handler) {
    if (ota_handler->mqtt_handle == NULL) {
        return;
    }
    char *topic = iot_get_common_topic(ota_handler->allocator, OTA_UPGRADE_NOTIFY_TOPIC, ota_handler->mqtt_handle->product_key, ota_handler->mqtt_handle->device_name);
    iot_mqtt_sub(ota_handler->mqtt_handle, topic, 1, _ota_rev_ota_notify_info, ota_handler);
    aws_mem_release(ota_handler->allocator, topic);
}

void _mqtt_sub_ota_upgrade_post_reply(iot_ota_handler_t *ota_handler) {
    if (ota_handler->mqtt_handle == NULL) {
        return;
    }
    char *topic = iot_get_common_topic(ota_handler->allocator, OTA_REQUEST_UPGRADE_REPLY_TOPIC, ota_handler->mqtt_handle->product_key, ota_handler->mqtt_handle->device_name);
    iot_mqtt_sub(ota_handler->mqtt_handle, topic, 1, _ota_rev_ota_upgrade_post_reply, ota_handler);
    aws_mem_release(ota_handler->allocator, topic);
}

void _ota_rev_ota_notify_info(struct aws_mqtt_client_connection *connection,
                              const struct aws_byte_cursor *topic,
                              const struct aws_byte_cursor *payload,
                              bool dup,
                              enum aws_mqtt_qos qos,
                              bool retain,
                              void *userdata) {

    iot_ota_handler_t *ota_handler = userdata;

    LOGD(TAG_OTA, "_ota_rev_ota_notify_info  topic = %.*s  payload = %.*s",
         AWS_BYTE_CURSOR_PRI(*topic),
         AWS_BYTE_CURSOR_PRI(*payload));

    //  sys/6476ee400c910eb5b69001a6/skin_left/ota/notify/639b2507886c5549e2afcb08
    //  payload = {"id":"d72ed64a221215220312","code":0,"data":{"type":"Upgrade","module":"default","dest_version":"1.1.0"}}

//    注意这里 ota_jobId 是来自于 topic
    struct aws_array_list topic_split_data_list;
    aws_array_list_init_dynamic(&topic_split_data_list, ota_handler->allocator, 8, sizeof(struct aws_byte_cursor));
    aws_byte_cursor_split_on_char(topic, '/', &topic_split_data_list);

    struct aws_byte_cursor ota_job_id_cur = {0};
    aws_array_list_get_at(&topic_split_data_list, &ota_job_id_cur, 5);

    struct aws_json_value *payloadJson = aws_json_value_new_from_string(ota_handler->allocator, *payload);
    // 这里的id
    struct aws_string *ota_job_id = aws_string_new_from_cursor(ota_handler->allocator, &ota_job_id_cur);
    struct aws_json_value *data_json = aws_json_value_get_from_object(payloadJson, aws_byte_cursor_from_c_str("data"));
    if (data_json != NULL) {
        struct aws_string *module = aws_json_get_string1_val(ota_handler->allocator, data_json, "module");
        struct aws_string *type = aws_json_get_string1_val(ota_handler->allocator, data_json, "type");
        if (aws_string_eq_c_str(type, "Upgrade")) {
            // 基于 id 请求详细信息
            for (int i = 0; i < ota_handler->device_info_array_size; i++) {
                iot_ota_device_info_t deviceInfo = ota_handler->device_info_array[i];
                if (aws_string_eq_c_str(module, deviceInfo.module)) {
                    iot_ota_request_oat_job_info(ota_handler, &deviceInfo, aws_string_c_str(ota_job_id));
                }
            }
        }
        aws_string_destroy_secure(module);
        aws_string_destroy_secure(type);
    }
    aws_string_destroy_secure(ota_job_id);
    aws_json_value_destroy(payloadJson);
    aws_array_list_clean_up(&topic_split_data_list);

}

void _ota_rev_ota_upgrade_post_reply(struct aws_mqtt_client_connection *connection,
                                     const struct aws_byte_cursor *topic,
                                     const struct aws_byte_cursor *payload,
                                     bool dup,
                                     enum aws_mqtt_qos qos,
                                     bool retain,
                                     void *userdata) {

    LOGD(TAG_OTA, "_ota_rev_ota_upgrade_post_reply  topic = %.*s  payload = %.*s",
         AWS_BYTE_CURSOR_PRI(*topic),
         AWS_BYTE_CURSOR_PRI(*payload));
    iot_ota_handler_t *ota_handler = userdata;

//    topic = sys/6476ee400c910eb5b69001a6/skin_left/ota/upgrade/post_reply
//    payload = {"id":"2371671114253805","code":0,"data":{"ota_job_id":"639b2507886c5549e2afcb08",
//    "timeout_in_minutes":100,"size":9901544,"dest_version":"1.1.0",
//    "url":"5cM4KIrD/6h60ezkD7ak74JkSCUrZGm6Ia3iv0u9WIn79+HgCRX5tNO9eb2wCYIJtL5urmTIYCjAj/pkZ03YTHV+L7DeWtdFkwO0zlBHNjDQbABd7Isf0cEXoXkSteMOioR6OGveEKKBhRTaCJB5uKOdJFTPH1P3fsSOwUHEWJHsOMsHaZWY9Ye8tXNkNg8HMEeWdkf0p1+JIF2SfpDz6IJLBG2cUeByCReL5rikqLC304lhLAe6nCMlKcvFZb34DURTFEK3K0y77cbjfbPHEYAbHtvhhANmAsEZTuXyE0LXOelHygZ2sGALH/tHriMUo6fsLEabmpnhT+u1QRbVHjLy/HX7BE2BtcGhByGdOqUDyUoKqmKMm+Hiv52pX/MybhwWh1DsJ0lq+B+m1QL+jfzBHCR95klpAOJNdA45n0NP8Rixw0jk3RqxcfxUDFLiG7wPlLNkLpgATy0ffun/ooJj5+JhRrksP8AWxa1hSGAZGTbv1Eb61wLa594mDGMN2pUEr5MkKcZSk+4HeRiMz5tS2LWPQcwnuRo8D2f8L24=",
//    "module":"default"}}

    struct aws_json_value *payloadJson = aws_json_value_new_from_string(ota_handler->allocator, *payload);
    iot_ota_job_info_t *ota_job_info = aws_mem_calloc(ota_handler->allocator, 1, sizeof(iot_ota_job_info_t));
    // 这里的id
    struct aws_json_value *data_json = aws_json_value_get_from_object(payloadJson, aws_byte_cursor_from_c_str("data"));
    if (data_json != NULL) {
        ota_job_info = _ota_data_json_to_ota_job_info(ota_handler->allocator, data_json);
        if (ota_job_info->url != NULL && ota_job_info->size > 0) {
            char kv_key[100];
            sprintf(kv_key, KEY_SAVE_JOB_INFO, ota_job_info->module);
            struct aws_byte_buf data_json_buf = aws_json_obj_to_bye_buf(ota_handler->allocator, data_json);
            struct aws_byte_cursor key_cur = aws_byte_cursor_from_c_str(kv_key);
            iot_add_kv_string(ota_handler->kv_ctx, key_cur, aws_byte_cursor_from_buf(&data_json_buf));

            if (ota_handler->get_jon_info_callback != NULL) {
                ota_handler->get_jon_info_callback(ota_handler, ota_job_info, ota_handler->get_jon_info_callback_user_data);
            }
        }
    }
    aws_json_value_destroy(payloadJson);

}


iot_ota_job_info_t *_ota_data_json_to_ota_job_info(struct aws_allocator *allocator, struct aws_json_value *data_json) {
    iot_ota_job_info_t *ota_job_info = aws_mem_calloc(allocator, 1, sizeof(iot_ota_job_info_t));
    ota_job_info->ota_job_id = aws_json_get_str(allocator, data_json, "ota_job_id");
    ota_job_info->dest_version = aws_json_get_str(allocator, data_json, "dest_version");
    ota_job_info->module = aws_json_get_str(allocator, data_json, "module");
    ota_job_info->url = aws_json_get_str(allocator, data_json, "url");
    ota_job_info->timeout_in_minutes = (int32_t) aws_json_get_num_val(data_json, "timeout_in_minutes");
    ota_job_info->size = (uint64_t) aws_json_get_num_val(data_json, "size");
    ota_job_info->sign = aws_json_get_str(allocator, data_json, "sign");
    return ota_job_info;
}

int32_t iot_ota_request_oat_job_info(iot_ota_handler_t *handler, iot_ota_device_info_t *device_info, char *job_id) {

    if (handler == NULL || device_info == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }

    struct aws_json_value *params_json = aws_json_value_new_object(handler->allocator);
    if (job_id != NULL) {
        aws_json_add_str_val_1(handler->allocator, params_json, "ota_job_id", job_id);
    }
    aws_json_add_str_val(params_json, "module", device_info->module);
    aws_json_add_str_val(params_json, "src_version", device_info->version);
    struct aws_json_value *payload_json = new_request_payload(handler->allocator, NULL, params_json);

    char *topic = iot_get_common_topic(handler->allocator, OTA_REQUEST_UPGRADE_TOPIC, handler->mqtt_handle->product_key, handler->mqtt_handle->device_name);
    struct aws_byte_cursor topic_cur = aws_byte_cursor_from_c_str(topic);
    struct aws_byte_buf payload_buf = aws_json_obj_to_bye_buf(handler->allocator, payload_json);
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&payload_buf);
    LOGD(TAG_OTA, "iot_ota_request_oat_job_info payload_cur = %.*s ", AWS_BYTE_CURSOR_PRI(payload_cur));
    aws_mqtt_client_connection_publish(handler->mqtt_handle->mqtt_connection, &topic_cur,
                                       AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                       _tm_mqtt_post_on_complete_fn,
                                       NULL);

    aws_mem_release(handler->allocator, topic);
    aws_byte_buf_clean_up(&payload_buf);
    aws_json_value_destroy(payload_json);
    return CODE_SUCCESS;
}

/**
 * 上报版本号, 同时也是 OTA完成的上报, 判断OTA升级是否成功, 是否到了新版本
 * @param handler
 * @param device_info_array
 * @param device_info_array_size
 * @return
 */
int32_t iot_ota_report_version(iot_ota_handler_t *handler, iot_ota_device_info_t *device_info_array, int device_info_array_size) {
    if (handler == NULL || device_info_array == NULL || device_info_array_size <= 0) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    struct aws_json_value *version_data_json = aws_json_value_new_object(handler->allocator);
    for (int i = 0; i < device_info_array_size; i++) {
        iot_ota_device_info_t deviceInfo = device_info_array[i];
        aws_json_add_str_val(version_data_json, deviceInfo.module, deviceInfo.version);
    }

    struct aws_json_value *payload_json = new_request_payload(handler->allocator, SDK_VERSION, version_data_json);

    char *topic = iot_get_common_topic(handler->allocator, OTA_VERSION_REPORT_TOPIC, handler->mqtt_handle->product_key, handler->mqtt_handle->device_name);
    struct aws_byte_cursor topic_cur = aws_byte_cursor_from_c_str(topic);
    struct aws_byte_buf payload_buf = aws_json_obj_to_bye_buf(handler->allocator, payload_json);
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&payload_buf);
    LOGD(TAG_OTA, "iot_ota_report_version payload_cur = %.*s ", AWS_BYTE_CURSOR_PRI(payload_cur));

    aws_mqtt_client_connection_publish(handler->mqtt_handle->mqtt_connection, &topic_cur,
                                       AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                       _tm_mqtt_post_on_complete_fn,
                                       NULL);

    aws_mem_release(handler->allocator, topic);
    aws_byte_buf_clean_up(&payload_buf);
    aws_json_value_destroy(payload_json);
    return CODE_SUCCESS;
}

int32_t iot_ota_report_progress_success(iot_ota_handler_t *handler, char *jobId, enum ota_upgrade_device_status_enum upgrade_device_status) {
    ota_process_status_t status = {
            .upgrade_device_status = upgrade_device_status,
    };
    return iot_ota_report_progress(handler, jobId, &status);
}

int32_t iot_ota_report_progress_failed(iot_ota_handler_t *handler, char *jobId, enum ota_upgrade_device_status_enum upgrade_device_status, int32_t error_code, char *result_desc) {
    ota_process_status_t status = {
            .upgrade_device_status = upgrade_device_status,
            .error_code = error_code,
            .result_desc =result_desc
    };
    return iot_ota_report_progress(handler, jobId, &status);
}


int32_t iot_ota_report_installing(iot_ota_handler_t *handler, char *jobId) {
    ota_process_status_t status = {
            .upgrade_device_status = UpgradeDeviceStatusInstalling,
    };
    return iot_ota_report_progress(handler, jobId, &status);
}

int32_t iot_ota_report_install_success(iot_ota_handler_t *handler, char *jobId) {
    ota_process_status_t status = {
            .upgrade_device_status = UpgradeDeviceStatusInstalled,
    };
    return iot_ota_report_progress(handler, jobId, &status);
}

int32_t iot_ota_report_install_failed(iot_ota_handler_t *handler, char *jobId, char *result_desc) {
    ota_process_status_t status = {
            .upgrade_device_status = UpgradeDeviceStatusFailed,
            .error_code = OTA_INSTALL_FAILED,
            .result_desc =result_desc
    };

    struct aws_hash_element *value_elem = NULL;

    // 标记待重试
    aws_hash_table_find(&handler->task_hash_map, jobId, &value_elem);
    iot_ota_job_task_info_t *last_task = NULL;
    if (value_elem != NULL) {
        last_task = (iot_ota_job_task_info_t *) value_elem->value;
        last_task->is_pending_to_retry = true;
    }
    return iot_ota_report_progress(handler, jobId, &status);
}


int32_t iot_ota_report_progress(iot_ota_handler_t *handler, char *jobId, ota_process_status_t *status) {
    if (handler == NULL || status == NULL || jobId == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    struct aws_json_value *data_json = aws_json_value_new_object(handler->allocator);
    aws_json_add_str_val(data_json, "status", iot_ota_job_status_enum_to_string(status->upgrade_device_status));
    aws_json_add_num_val(data_json, "result_code", status->error_code);
    aws_json_add_str_val(data_json, "result_desc", status->result_desc);
    aws_json_add_num_val(data_json, "time", (double) get_current_time_mil());
    struct aws_json_value *payload_json = new_request_payload(handler->allocator, SDK_VERSION, data_json);

    char *topic = iot_get_topic_with_1_c_str_param(handler->allocator, OTA_UPGRADE_PROGRESS_REPORT_TOPIC, handler->mqtt_handle->product_key, handler->mqtt_handle->device_name,
                                                   jobId);
    struct aws_byte_cursor topic_cur = aws_byte_cursor_from_c_str(topic);
    struct aws_byte_buf payload_buf = aws_json_obj_to_bye_buf(handler->allocator, payload_json);
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&payload_buf);
    LOGD(TAG_OTA, "iot_ota_report_progress payload_cur = %.*s ", AWS_BYTE_CURSOR_PRI(payload_cur));

    aws_mqtt_client_connection_publish(handler->mqtt_handle->mqtt_connection, &topic_cur,
                                       AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                       _tm_mqtt_post_on_complete_fn,
                                       NULL);


    aws_mem_release(handler->allocator, topic);
    aws_byte_buf_clean_up(&payload_buf);
    aws_json_value_destroy(payload_json);
    return CODE_SUCCESS;
}

static void s_auto_request_oat_info_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    iot_ota_handler_t *handler = arg;
    request_device_job_info_inner(handler);
    if (handler->auto_request_ota_info_interval_sec > 0) {
        iot_core_post_delay_task(task, handler->auto_request_ota_info_interval_sec);
    } else {
        aws_mem_release(handler->allocator, task);
    }

}

void request_device_job_info_inner(iot_ota_handler_t *handler) {
    for (int i = 0; i < handler->device_info_array_size; i++) {
        iot_ota_device_info_t deviceInfo = handler->device_info_array[i];

        iot_ota_request_oat_job_info(handler, &deviceInfo, NULL);
    }
}

int32_t iot_start_auto_request_oat_info(iot_ota_handler_t *handler) {
    if (handler == NULL) {
        return CODE_USER_INPUT_NULL_POINTER;
    }
    if (handler->device_info_array == NULL || handler->device_info_array_size <= 0) {
        return OTA_DEVICE_INFO_NOT_SET;
    }
    request_device_job_info_inner(handler);

    // 延迟重试
    struct aws_task *retry_task = aws_mem_acquire(handler->allocator, sizeof(struct aws_task));
    aws_task_init(retry_task, s_auto_request_oat_info_task, handler, "retry_ota_task");
    iot_core_post_delay_task(retry_task, handler->auto_request_ota_info_interval_sec);
}


void iot_ota_save_job_task_info(iot_ota_job_task_info_t *task_info) {
    struct aws_json_value *task_json = aws_json_value_new_object(task_info->ota_handler->allocator);
    aws_json_add_str_val(task_json, "ota_file_path", task_info->ota_file_path);
    aws_json_add_aws_string_val1(task_info->ota_handler->allocator, task_json, "decode_url", task_info->decode_url);
    aws_json_add_num_val1(task_info->ota_handler->allocator, task_json, "retry_time", task_info->retry_time);
    aws_json_add_num_val1(task_info->ota_handler->allocator, task_json, "upgrade_device_status", task_info->upgrade_device_status);
    if (task_info->download_handler != NULL && task_info->download_handler->download_response != NULL && task_info->download_handler->download_response->down_file != NULL) {
        aws_json_add_aws_string_val1(task_info->ota_handler->allocator, task_json, "ota_file_path", task_info->download_handler->download_response->down_file);
    }
    aws_json_obj_to_bye_buf(task_info->ota_handler->allocator, task_json);

    char kv_key[100];
    sprintf(kv_key, KEY_SAVE_TASK_INFO, task_info->server_job_info->ota_job_id);
    struct aws_byte_buf data_json_buf = aws_json_obj_to_bye_buf(task_info->ota_handler->allocator, task_json);
    struct aws_byte_cursor key_cur = aws_byte_cursor_from_c_str(kv_key);
    iot_add_kv_string(task_info->ota_handler->kv_ctx, key_cur, aws_byte_cursor_from_buf(&data_json_buf));
}


void iot_ota_delete_job_task_info(iot_ota_job_task_info_t *task_info) {
    char kv_key[100];
    sprintf(kv_key, KEY_SAVE_TASK_INFO, task_info->server_job_info->ota_job_id);
    iot_remove_key_str(task_info->ota_handler->kv_ctx, kv_key);
}

