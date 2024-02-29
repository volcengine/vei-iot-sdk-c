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

#include <aws/common/file.h>
#include <aws/common/thread_scheduler.h>
#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/common/condition_variable.h>
#include "aws/common/common.h"
#include "aws/common/string.h"
#include "aws/common/date_time.h"

#include "iot_log.h"
#include "iot_core.h"
#include "iot_util.h"
#include "iot_core_header.h"


#define MAX_LOG_LINE_PREFIX_SIZE 150
#define LOG_SEND_MIN_INTERVAL_SEC 5
#define LOG_SEND_MIN_LOG_LINES 30


struct iot_log_ctx g_logCtx_internal;
struct iot_log_ctx *g_logCtx;

static const char *s_log_level_strings[COUNT] = {"NONE", "FATAL", "ERROR", "WARN", "INFO", "DEBUG"};

void _log_level_to_string(enum aiot_log_level log_level, const char **level_string) {
    if (level_string != NULL) {
        *level_string = s_log_level_strings[log_level];
    }
}

enum aiot_log_level _log_string_to_level(struct aws_byte_cursor *lowest_level_cur) {
    if (aws_byte_cursor_eq_c_str(lowest_level_cur, "debug") || aws_byte_cursor_eq_c_str(lowest_level_cur, "DEBUG")) {
        return DEBUG;
    } else if (aws_byte_cursor_eq_c_str(lowest_level_cur, "info") || aws_byte_cursor_eq_c_str(lowest_level_cur, "INFO")) {
        return INFO;
    } else if (aws_byte_cursor_eq_c_str(lowest_level_cur, "warn") || aws_byte_cursor_eq_c_str(lowest_level_cur, "WARN")) {
        return WARN;
    } else if (aws_byte_cursor_eq_c_str(lowest_level_cur, "error") || aws_byte_cursor_eq_c_str(lowest_level_cur, "ERROR")) {
        return ERROR;
    } else if (aws_byte_cursor_eq_c_str(lowest_level_cur, "fatal") || aws_byte_cursor_eq_c_str(lowest_level_cur, "FATAL")) {
        return FATAL;
    } else {
        return DEBUG;
    }
}

//定义 logCtx 全局变量

//定时任务, 触发日志写入文件, 以及发送给服务端
static void s_send_log_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    if (status == AWS_TASK_STATUS_CANCELED || g_logCtx == NULL || g_logCtx->finished) {
        return;
    }

    // 发射写入日志的任务,
    if (aws_array_list_length(&g_logCtx->pending_log_lines) > 0) {
        aws_mutex_lock(&g_logCtx->sync);
        g_logCtx->isTimeToSendLog = true;
        aws_condition_variable_notify_one(&g_logCtx->pending_line_signal);
        aws_mutex_unlock(&g_logCtx->sync);
    }

    // 下一次任务处理
    iot_core_post_delay_task(g_logCtx->send_log_task, g_logCtx->option.check_write_file_interval_sec);
}

void iot_log_init(char *save_dir_path) {
    struct iot_log_ctx_option option;
    option.check_write_file_line_count = LOG_SEND_MIN_LOG_LINES;
    option.check_write_file_interval_sec = LOG_SEND_MIN_INTERVAL_SEC;
    if (save_dir_path == NULL || strlen(save_dir_path) == 0) {
        iot_log_init_with_option("iot_logs", option);
    } else {
        iot_log_init_with_option(save_dir_path, option);
    }
}

/**
 * 日志 初始化, 需要尽早调用
 * @param allocator
 */
void iot_log_init_with_option(char *save_dir_path, struct iot_log_ctx_option option) {
    // 重复初始化问题处理
    if (g_logCtx != NULL) {
        return;
    }

    g_logCtx = &g_logCtx_internal;
    AWS_ZERO_STRUCT(*g_logCtx);
    g_logCtx->save_dir_path = save_dir_path;
    g_logCtx->allocator = get_iot_core_context()->alloc;
    g_logCtx->option = option;

    aws_mutex_init(&g_logCtx->sync);
    aws_array_list_init_dynamic(&g_logCtx->pending_log_lines, g_logCtx->allocator, g_logCtx->option.check_write_file_line_count, sizeof(struct iot_log_obj *));
    aws_condition_variable_init(&g_logCtx->pending_line_signal);

    // 后台日志写入到文件的现场
    aws_thread_init(&g_logCtx->background_thread, g_logCtx->allocator);
    struct aws_thread_options thread_options = {.stack_size = 0};
    aws_thread_launch(&g_logCtx->background_thread, _s_background_thread_writer, g_logCtx, &thread_options);


    // 创建日志保存目录
    struct aws_string *save_dir_path_string = aws_string_new_from_c_str(g_logCtx->allocator, save_dir_path);
    if (aws_directory_exists(save_dir_path_string) != true) {
        aws_directory_create(save_dir_path_string);
    }
    aws_string_destroy_secure(save_dir_path_string);

    // 初始化日志写入文件
    struct aws_string *newFilPath = iot_get_log_file_name();
    g_logCtx->log_file = aws_fopen_safe(newFilPath, aws_string_new_from_c_str(g_logCtx->allocator, "a+"));
    g_logCtx->file_path = newFilPath;

    // 初始化 线程的定时异步任务
    g_logCtx->send_log_task = aws_mem_acquire(g_logCtx->allocator, sizeof(struct aws_task));
    aws_task_init(g_logCtx->send_log_task, s_send_log_task_fn, g_logCtx, "send_log_task");
    iot_core_post_delay_task(g_logCtx->send_log_task, g_logCtx->option.check_write_file_interval_sec);

}


void iot_log_set_on_log_save_fn(iot_on_log_save_fn *on_save_fn, void *user_data) {
    if (g_logCtx == NULL) {
        return;
    }
    g_logCtx->on_log_save_fn = on_save_fn;
    g_logCtx->on_log_save_fn_user_data = user_data;
}


/**
 * 设置日志写入文件的触发 行数阈值, 超过这个阈值 则写入到文件
 * @param sec
 */
void log_set_check_write_file_line_count(int32_t count) {
    if (g_logCtx == NULL) {
        return;
    }
    g_logCtx->option.check_write_file_line_count = count;
}

//// 外部注入 设备 Ctx , 主要是在吧日志发送给服务端时需要
//void log_set_device_ctx(arenal_device_ctx_t *device_ctx) {
//    g_logCtx->ctx = device_ctx;
//}

// check 文件名 是否是是当前日期
void _check_file() {
    struct aws_string *newFilPath = iot_get_log_file_name();
    if (g_logCtx->log_file == NULL) {
        g_logCtx->log_file = aws_fopen(aws_string_c_str(newFilPath), "a+");
        g_logCtx->file_path = newFilPath;
    } else if (!aws_string_eq(g_logCtx->file_path, newFilPath)) {
        fflush(g_logCtx->log_file);
        fclose(g_logCtx->log_file);
        // 清除之前申请的内存
        aws_string_destroy_secure(g_logCtx->file_path);
        g_logCtx->log_file = aws_fopen(aws_string_c_str(newFilPath), "a+");
        g_logCtx->file_path = newFilPath;
    } else {
        aws_string_destroy_secure(newFilPath);
    }
}


char *iot_get_log_file_dir() {
    if (g_logCtx == NULL) {
        return NULL;
    }
    return g_logCtx->save_dir_path;
}


// 获取 log 文件路径
struct aws_string *iot_get_log_file_name() {
    char filename_array[1024];
    AWS_ZERO_ARRAY(filename_array);
    struct aws_byte_buf filename_buf = aws_byte_buf_from_empty_array(filename_array, sizeof(filename_array));

    aws_byte_buf_write_from_whole_cursor(&filename_buf, aws_byte_cursor_from_c_str(g_logCtx->save_dir_path));
    aws_byte_buf_write_from_whole_cursor(&filename_buf, aws_byte_cursor_from_c_str(AWS_PATH_DELIM_STR));
    aws_byte_buf_write_from_whole_cursor(&filename_buf, aws_byte_cursor_from_c_str("iot_"));
    // 获取时间字符串
    struct aws_date_time current_time;
    aws_date_time_init_now(&current_time);

    uint8_t date_output[AWS_DATE_TIME_STR_MAX_LEN];
    AWS_ZERO_ARRAY(date_output);
    struct aws_byte_buf str_output = aws_byte_buf_from_array(date_output, sizeof(date_output));
    str_output.len = 0;
    aws_date_time_to_local_time_short_str(&current_time, AWS_DATE_FORMAT_ISO_8601, &str_output);

    aws_byte_buf_write_from_whole_cursor(&filename_buf, aws_byte_cursor_from_buf(&str_output));

    aws_byte_buf_write_from_whole_cursor(&filename_buf, aws_byte_cursor_from_c_str(".log"));

    // 这里申请了内存, 会在 check_file 中销毁
    return aws_string_new_from_array(g_logCtx->allocator, filename_buf.buffer, filename_buf.len);
}


/**
 * 后台线程写入文件的等待条件,
 *
 * @param context
 * @return
 */
static bool s_background_wait(void *context) {
    if (g_logCtx == NULL) {
        return true;
    }
    struct iot_log_ctx *impl = (struct iot_log_ctx *) context;
    /*
     * Condition variable predicates are checked under mutex protection
     */
    return impl->finished ||
           // 打到了最大数量
           aws_array_list_length(&impl->pending_log_lines) > g_logCtx->option.check_write_file_line_count ||
           // 到了最小间隔时间
           impl->isTimeToSendLog;
}

static void _s_background_thread_writer(void *thread_data) {
    (void) thread_data;
    struct iot_log_ctx *logCtx = (struct iot_log_ctx *) thread_data;

    struct aws_array_list log_lines;
    aws_array_list_init_dynamic(&log_lines, logCtx->allocator, LOG_SEND_MIN_LOG_LINES, sizeof(struct iot_log_obj *));
    while (true) {
        aws_mutex_lock(&logCtx->sync);

        // 等待条件触发
        aws_condition_variable_wait_pred(&logCtx->pending_line_signal, &logCtx->sync, s_background_wait, logCtx);
        if (g_logCtx == NULL) {
            break;
        }

        bool finished = logCtx->finished;
        if (finished) {
            aws_mutex_unlock(&logCtx->sync);
            break;
        }

        size_t line_count = aws_array_list_length(&logCtx->pending_log_lines);
        if (line_count == 0) {
            aws_mutex_unlock(&logCtx->sync);
            continue;
        }

        g_logCtx->isTimeToSendLog = false;
        // 交换全局变量中的数据, 方便 pending_log_lines 可以继续写入数据
        // 这里需要注意锁的处理,  写入到list 也需要加锁才行, 不然数据会有问题, 具体看 s_background_channel_send
        aws_array_list_swap_contents(&logCtx->pending_log_lines, &log_lines);
        aws_mutex_unlock(&logCtx->sync);

        // 检查文件名是否需要更换
        _check_file();
        // 上报日志到服务端.
        if (g_logCtx->on_log_save_fn != NULL) {
            g_logCtx->on_log_save_fn(&log_lines, g_logCtx->on_log_save_fn_user_data);
        }
        // 写入到文件
        for (size_t i = 0; i < line_count; ++i) {
            struct iot_log_obj *logObj = NULL;
            AWS_FATAL_ASSERT(aws_array_list_get_at(&log_lines, &logObj, i) == AWS_OP_SUCCESS);
            // 写入文件
            size_t length = logObj->logContent->len;
            if (logCtx->log_file == NULL || fwrite(logObj->logContent->bytes, 1, length, logCtx->log_file) < length) {
                printf("log write to file failed log_file = %p\n", logCtx->log_file);
            }

            // 销毁对应的日志数据
            aws_string_destroy_secure(logObj->logContent);
            aws_mem_release(logCtx->allocator, logObj);
        }


        // 刷新文件
        fflush(logCtx->log_file);
        aws_array_list_clear(&log_lines);
    }

    aws_array_list_clean_up(&log_lines);
}

// 线程局部变量, 用于获取当前的线程Id
AWS_THREAD_LOCAL struct {
    bool is_valid;
    char repr[AWS_THREAD_ID_T_REPR_BUFSZ];
} arenal_logging_thread_id = {.is_valid = false};


// LOGD LOGE  这行宏对于的方法,
void sdk_log_print(enum aiot_log_level level, const char *logType, const char *tag, const char *format, ...) {
    va_list format_args;
    va_start(format_args, format);
    if (g_logCtx == NULL || g_logCtx->finished) {
        return;
    }
    struct aws_allocator *allocator = g_logCtx->allocator;
    struct iot_log_obj *logObj = aws_mem_calloc(allocator, 1, sizeof(struct iot_log_obj));

    // 日志格式化, 并写入到 logObj;
    _log_format(level, logObj, logType, tag, format, format_args);
    va_end(format_args);


    if (g_logCtx != NULL) {
        // 写入到 list
        _s_background_channel_send(g_logCtx, logObj);
    }
}

static int _s_background_channel_send(struct iot_log_ctx *impl, struct iot_log_obj *logObj) {
    // 写入数据到 list 也需要加锁, 防止多线程数据异常

    aws_mutex_lock(&impl->sync);
    aws_array_list_push_back(&impl->pending_log_lines, &logObj);
    aws_condition_variable_notify_one(&impl->pending_line_signal);
    aws_mutex_unlock(&impl->sync);
    return AWS_OP_SUCCESS;
}

// 日志格式化
void _log_format(enum aiot_log_level level, struct iot_log_obj *logObj, const char *logType, const char *tag,
                 const char *format,
                 va_list format_args) {
    va_list tmp_args;
    va_copy(tmp_args, format_args);
#ifdef _WIN32
    int required_length = _vscprintf(format, tmp_args) + 10;
#else
    int required_length = vsnprintf(NULL, 0, format, tmp_args) + 10;
#endif
    va_end(tmp_args);

    struct aws_allocator *allocator = g_logCtx->allocator;


    // 这里创建合适大小的 string 对象
    int total_length = required_length + MAX_LOG_LINE_PREFIX_SIZE;
    struct aws_string *raw_string = aws_mem_calloc(allocator, 1, sizeof(struct aws_string) + total_length);
    logObj->logContent = raw_string;
    logObj->logType = logType;
    logObj->log_level = level;

    // 此时 log_line_buffer  为空
    char *log_line_buffer = (char *) raw_string->bytes;

    // 获取 level String
    const char *levelStr = NULL;
    _log_level_to_string(level, &levelStr);
    logObj->logLevelStr = levelStr;

    // 获取时间字符串
    struct aws_date_time current_time;
    aws_date_time_init_now(&current_time);
    logObj->time = aws_date_time_as_millis(&current_time);

    uint8_t date_output[AWS_DATE_TIME_STR_MAX_LEN];
    AWS_ZERO_ARRAY(date_output);
    struct aws_byte_buf str_output_buf = aws_byte_buf_from_array(date_output, sizeof(date_output));
    str_output_buf.len = 0;
    aws_date_time_to_local_time_str(&current_time, AWS_DATE_FORMAT_ISO_8601, &str_output_buf);

    // 获取线程 id
    if (!arenal_logging_thread_id.is_valid) {
        aws_thread_id_t current_thread_id = aws_thread_current_thread_id();
        if (aws_thread_id_t_to_string(current_thread_id, arenal_logging_thread_id.repr, AWS_THREAD_ID_T_REPR_BUFSZ)) {
            return;
        }
        arenal_logging_thread_id.is_valid = true;
    }


    // 写入日志前缀
    sprintf(log_line_buffer, "[%s] [%s] [%.*s] [%s] %s : ", logType, levelStr,
            AWS_BYTE_BUF_PRI(str_output_buf), arenal_logging_thread_id.repr, tag);
    // 释放申请的内存

    int curIndex = secure_strlen(log_line_buffer);
    // 写入日志具体内容


#ifdef _WIN32
    vsnprintf_s(log_line_buffer + curIndex, total_length - curIndex,  _TRUNCATE, format, format_args);
#else
    vsnprintf(log_line_buffer + curIndex, total_length - curIndex, format, format_args);
#endif /* _WIN32 */

    // 写入 换行符
    curIndex = secure_strlen(log_line_buffer);
    snprintf(log_line_buffer + curIndex, total_length - curIndex, "\n");

    *(struct aws_allocator **) (&raw_string->allocator) = allocator;
    *(size_t *) (&raw_string->len) = secure_strlen(log_line_buffer);

    // 输出到控制台
    printf("%s", log_line_buffer);
}


void iot_log_release() {
    g_logCtx->finished = true;
    size_t line_count = aws_array_list_length(&g_logCtx->pending_log_lines);
    // 写入到文件
    for (size_t i = 0; i < line_count; ++i) {
        struct iot_log_obj *logObj = NULL;
        if (aws_array_list_get_at(&g_logCtx->pending_log_lines, &logObj, i) == AWS_OP_SUCCESS) {
            // 销毁对应的日志数据
            aws_string_destroy_secure(logObj->logContent);
            aws_mem_release(g_logCtx->allocator, logObj);
        }
    }
    aws_array_list_clean_up(&g_logCtx->pending_log_lines);
    aws_string_destroy_secure(g_logCtx->file_path);
    aws_thread_clean_up(&g_logCtx->background_thread);
    aws_mem_release(g_logCtx->allocator, g_logCtx->send_log_task);

    if (g_logCtx != NULL) {
        aws_mem_release(g_logCtx->allocator, g_logCtx);
    }
    g_logCtx = NULL;
}