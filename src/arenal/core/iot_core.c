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

#include <aws/common/thread_scheduler.h>
#include <aws/common/clock.h>
#include "iot_core.h"
#include "iot_core_header.h"

// 定义全局的core context 变量
core_context_t g_origin_core_context;

core_context_t *g_core_context = NULL;

bool s_arenal_core_initialized = false;

void iot_core_init() {
    if (!s_arenal_core_initialized) {
        s_arenal_core_initialized = true;
        g_core_context = &g_origin_core_context;
        g_core_context->alloc = aws_default_allocator();
        aws_common_library_init(g_core_context->alloc);
        aws_io_library_init(g_core_context->alloc);

        g_core_context->event_loop_group = aws_event_loop_group_new_default(g_core_context->alloc, 2, NULL);

        struct aws_host_resolver_default_options resolver_options = {
                .el_group = g_core_context->event_loop_group,
                .max_entries = 4,
        };
        g_core_context->host_resolver = aws_host_resolver_new_default(g_core_context->alloc, &resolver_options);

        struct aws_client_bootstrap_options bootstrap_options = {
                .event_loop_group = g_core_context->event_loop_group,
                .host_resolver = g_core_context->host_resolver,
        };

        aws_tls_ctx_options_init_default_client(&g_core_context->tls_ctx_options, g_core_context->alloc);
        g_core_context->tls_ctx = aws_tls_client_ctx_new(g_core_context->alloc, &g_core_context->tls_ctx_options);
        aws_tls_ctx_options_set_alpn_list(&g_core_context->tls_ctx_options, "http/1.1");


        g_core_context->client_bootstrap = aws_client_bootstrap_new(g_core_context->alloc, &bootstrap_options);


        struct aws_thread_options thread_options = {.stack_size = 0};
        g_core_context->thread_scheduler = aws_thread_scheduler_new(g_core_context->alloc, &thread_options);

        aws_hash_table_init(&g_core_context->device_secret_map,  g_core_context->alloc, 2, aws_hash_c_string, aws_hash_callback_c_str_eq, NULL, NULL);

        struct aws_logger_standard_options logger_options = {
                .level = AWS_LOG_LEVEL_WARN,
                .file = stdout,
        };
        aws_logger_init_standard(&g_core_context->logger, g_core_context->alloc, &logger_options);
        aws_logger_set(&g_core_context->logger);

    }
}

void iot_core_post_delay_task(struct aws_task *task, uint64_t delay_time_sec) {
    uint64_t task_timestamp = 0;
    aws_high_res_clock_get_ticks(&task_timestamp);
    task_timestamp = task_timestamp + ((uint64_t) delay_time_sec * AWS_TIMESTAMP_NANOS);
    aws_thread_scheduler_schedule_future(get_iot_core_context()->thread_scheduler, task, task_timestamp);
}


core_context_t *get_iot_core_context(void) {
    return g_core_context;
}

void iot_core_de_init() {
    if (s_arenal_core_initialized) {
        aws_event_loop_group_release(g_core_context->event_loop_group);
        aws_host_resolver_release(g_core_context->host_resolver);
        aws_tls_ctx_release(g_core_context->tls_ctx);
        aws_client_bootstrap_release(g_core_context->client_bootstrap);
        aws_thread_scheduler_release(g_core_context->thread_scheduler);
        aws_tls_ctx_options_clean_up(&g_core_context->tls_ctx_options);
        aws_task_scheduler_clean_up(&g_core_context->scheduler);
    }
}
