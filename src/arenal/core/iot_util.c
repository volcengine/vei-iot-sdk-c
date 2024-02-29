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

#include <aws/common/device_random.h>
#include <aws/common/date_time.h>
#include <aws/common/encoding.h>
#include <aws/cal/hmac.h>
#include <aws/common/uuid.h>
#include <openssl/md5.h>
#include <aws/common/clock.h>
#include <aws/common/thread_scheduler.h>
#include <aws/common/json.h>
#include <openssl/aes.h>
#include "iot_util.h"
#include "stdlib.h"
#include "time.h"
#include "iot_core.h"
#include "iot_log.h"
#include "iot_core_header.h"

#define TAG_IOT_UTIL  "iot_util"


int32_t arenal_get_random_num() {
    srand((unsigned) time(NULL));
    return rand();
}

struct aws_string *get_uuid(struct aws_allocator *allocator) {
    struct aws_uuid uuid;
    aws_uuid_init(&uuid);

    uint8_t uuid_array[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_array(uuid_array, sizeof(uuid_array));
    uuid_buf.len = 0;
    aws_uuid_to_str(&uuid, &uuid_buf);
    struct aws_string *uuid_string = aws_string_new_from_buf(allocator, &uuid_buf);
    return uuid_string;
}

const char* get_uuid_c_str(struct aws_allocator* allocator) {
    struct aws_string* uuid = get_uuid(allocator);
    const char* uuid_c_str = (const char*) aws_mem_acquire(get_iot_core_context()->alloc, uuid->len);
    memcpy(uuid_c_str, uuid->bytes, uuid->len);
    aws_mem_release(allocator, uuid);
    return uuid_c_str;
}

char *aws_cur_to_char_str(
        struct aws_allocator *allocator,
        const struct aws_byte_cursor *cur) {
    AWS_PRECONDITION(allocator);
    size_t malloc_size;
    if (aws_add_size_checked(sizeof(char), cur->len + 1, &malloc_size)) {
        return NULL;
    }
    char *str = aws_mem_acquire(allocator, malloc_size);
    memset(str, 0, malloc_size);
    if (!str) {
        return NULL;
    }
    if (cur->len > 0) {
        memcpy((void *) str, cur->ptr, cur->len);
    }
    return str;
}


char *aws_buf_to_char_str(
        struct aws_allocator *allocator,
        const struct aws_byte_buf *cur) {
    AWS_PRECONDITION(allocator);
    size_t malloc_size;
    if (aws_add_size_checked(sizeof(char), cur->len + 1, &malloc_size)) {
        return NULL;
    }
    char *str = aws_mem_acquire(allocator, malloc_size);
    memset(str, 0, malloc_size);
    if (!str) {
        return NULL;
    }
    if (cur->len > 0) {
        memcpy((void *) str, cur->buffer, cur->len);
    }
    return str;
}

char *aws_string_new_char_str(
        struct aws_allocator *allocator,
        const struct aws_string *cur) {
    AWS_PRECONDITION(allocator);
    size_t malloc_size;
    if (aws_add_size_checked(sizeof(char), cur->len + 1, &malloc_size)) {
        return NULL;
    }
    char *str = aws_mem_acquire(allocator, malloc_size);
    memset(str, 0, malloc_size);
    if (!str) {
        return NULL;
    }
    if (cur->len > 0) {
        memcpy((void *) str, cur->bytes, cur->len);
    }
    return str;
}


char *get_random_string_with_time_suffix(struct aws_allocator *allocator) {
    uint8_t randomVal = 0;
    aws_device_random_u8(&randomVal);
    struct aws_date_time current_time;
    aws_date_time_init_now(&current_time);
    char *outStr = aws_mem_acquire(allocator, 50);
    sprintf(outStr, "%d%llu", randomVal, aws_date_time_as_millis(&current_time));
    return outStr;
}

struct aws_string *get_random_string_id(struct aws_allocator *allocator) {
    const char* result_c_str =  get_random_string_id_c_str(allocator);
    struct aws_string *result = aws_string_new_from_c_str(allocator, result_c_str);
    aws_mem_release(allocator, result_c_str);
    return result;
}

const char* get_random_string_id_c_str(struct aws_allocator* allocator) {
    uint8_t randomVal = 0;
    aws_device_random_u8(&randomVal);
    struct aws_date_time current_time;
    aws_date_time_init_now(&current_time);
    char* random_c_str = aws_mem_calloc(allocator, 1, 64);
    sprintf(random_c_str, "%d%llu", randomVal, aws_date_time_as_millis(&current_time));
    return random_c_str;
}

int get_random_num_uint64(uint64_t* out) {
    return aws_device_random_u64(out);
}

int get_random_num_uint32(uint32_t* out) {
    return aws_device_random_u32(out);
}

struct aws_string *
format_unique_fieldname(struct aws_allocator *allocator, const char *moduleKey, const char *identifier) {
    int strLen = strlen(moduleKey) + strlen(identifier) + 1;
    char outStr[strLen];
    sprintf(outStr, "%s:%s", moduleKey, identifier);
    return aws_string_new_from_c_str(allocator, outStr);
}


struct aws_string *get_date_format_iso_8601_data_str(struct aws_allocator *allocator) {
    struct aws_date_time current_time;
    aws_date_time_init_now(&current_time);
    uint8_t date_output[AWS_DATE_TIME_STR_MAX_LEN];
    AWS_ZERO_ARRAY(date_output);
    struct aws_byte_buf timeStr = aws_byte_buf_from_array(date_output, sizeof(date_output));
    timeStr.len = 0;
    aws_date_time_to_local_time_str(&current_time, AWS_DATE_FORMAT_ISO_8601, &timeStr);
    return aws_string_new_from_buf(allocator, &timeStr);
}


uint64_t get_current_time_mil() {
    struct aws_date_time current_time;
    aws_date_time_init_now(&current_time);
    return aws_date_time_as_millis(&current_time);
}

uint64_t get_current_time_sec() {
    struct aws_date_time current_time;
    aws_date_time_init_now(&current_time);
    return aws_date_time_as_epoch_secs(&current_time);
}


struct aws_json_value *
new_reply_payload(struct aws_allocator *alloc, struct aws_byte_cursor idCur, int code, struct aws_json_value *data) {
    struct aws_json_value *replyPayload = aws_json_value_new_object(alloc);
    aws_json_value_add_to_object(replyPayload, aws_byte_cursor_from_c_str("ID"),
                                 aws_json_value_new_string(alloc, idCur));
    aws_json_value_add_to_object(replyPayload, aws_byte_cursor_from_c_str("Code"),
                                 aws_json_value_new_number(alloc, (double) code));
    if (data != NULL) {
        aws_json_value_add_to_object(replyPayload, aws_byte_cursor_from_c_str("Data"), data);
    }
    return replyPayload;
}

struct aws_json_value *
new_request_payload(struct aws_allocator *alloc, const char *version,
                    struct aws_json_value *data) {
    struct aws_json_value *replyPayload = aws_json_value_new_object(alloc);
    char *id = get_random_string_with_time_suffix(get_iot_core_context()->alloc);
    aws_json_value_add_to_object(replyPayload, aws_byte_cursor_from_c_str("id"),
                                 aws_json_value_new_string(alloc, aws_byte_cursor_from_c_str(id)));

    aws_mem_release(get_iot_core_context()->alloc, id);
    char *real_version_str = version;
    if (real_version_str == NULL) {
        real_version_str = SDK_VERSION;
    }
    aws_json_value_add_to_object(replyPayload, aws_byte_cursor_from_c_str("version"),
                                 aws_json_value_new_string(alloc, aws_byte_cursor_from_c_str(real_version_str)));
    if (data != NULL) {
        aws_json_value_add_to_object(replyPayload, aws_byte_cursor_from_c_str("params"), data);
    }
    return replyPayload;
}


struct aws_string *aws_json_get_string_val(struct aws_json_value *data_json, const char *key) {
    struct aws_json_value *json_value = aws_json_value_get_from_object(data_json, aws_byte_cursor_from_c_str(key));
    struct aws_byte_cursor value_cur = {0};
    aws_json_value_get_string(json_value, &value_cur);
    return aws_string_new_from_cursor(get_iot_core_context()->alloc, &value_cur);

}


struct aws_string *aws_json_get_string1_val(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key) {
    struct aws_json_value *json_value = aws_json_value_get_from_object(data_json, aws_byte_cursor_from_c_str(key));
    struct aws_byte_cursor value_cur = {0};
    aws_json_value_get_string(json_value, &value_cur);
    return aws_string_new_from_cursor(allocator, &value_cur);
}


struct aws_byte_cursor aws_json_get_str_byte_cur_val(struct aws_json_value *data_json, const char *key) {
    struct aws_json_value *json_val = aws_json_value_get_from_object(data_json,
                                                                     aws_byte_cursor_from_c_str(
                                                                             key));
    struct aws_byte_cursor cur_val = {0};
    aws_json_value_get_string(json_val, &cur_val);
    return cur_val;
}


struct aws_byte_buf aws_json_get_json_obj_to_bye_buf(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key) {
    struct aws_json_value *json_val = aws_json_value_get_from_object(data_json, aws_byte_cursor_from_c_str(key));
    struct aws_byte_buf result_string_buf;
    aws_byte_buf_init(&result_string_buf, allocator, 0);
    aws_byte_buf_append_json_string(json_val, &result_string_buf);
    return result_string_buf;
}

struct aws_json_value* aws_json_get_json_obj(struct  aws_allocator* allocator, struct aws_json_value* data_json, const char* key) {
    struct aws_json_value* json_val = aws_json_value_get_from_object(data_json, aws_byte_cursor_from_c_str(key));
    return json_val;
}


struct aws_byte_buf aws_json_obj_to_bye_buf(struct aws_allocator *allocator, struct aws_json_value *data_json) {
    struct aws_byte_buf result_string_buf;
    aws_byte_buf_init(&result_string_buf, allocator, 0);
    aws_byte_buf_append_json_string(data_json, &result_string_buf);
    return result_string_buf;
}


char *aws_json_get_str(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key) {
    struct aws_byte_cursor cur_val = aws_json_get_str_byte_cur_val(data_json, key);
    return aws_cur_to_char_str(allocator, &cur_val);
}

void aws_json_add_str_val(struct aws_json_value *data_json, const char *key, const char *value) {
    if (value == NULL) {
        aws_json_value_remove_from_object(data_json, aws_byte_cursor_from_c_str(key));
        return;
    }
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key),
                                 aws_json_value_new_string(get_iot_core_context()->alloc, aws_byte_cursor_from_c_str(value)));
}

void aws_json_add_str_val_1(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, const char *value) {
    if (value == NULL) {
        aws_json_value_remove_from_object(data_json, aws_byte_cursor_from_c_str(key));
        return;
    }
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key), aws_json_value_new_string(allocator, aws_byte_cursor_from_c_str(value)));
}


void aws_json_add_json_str_obj(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, const char *value) {
    if (value == NULL) {
        aws_json_value_remove_from_object(data_json, aws_byte_cursor_from_c_str(key));
        return;
    }
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key), aws_json_value_new_from_string(allocator, aws_byte_cursor_from_c_str(value)));
}

void aws_json_add_json_obj(struct aws_json_value *data_json, const char *key, struct aws_json_value *value) {
    if (value == NULL) {
        aws_json_value_remove_from_object(data_json, aws_byte_cursor_from_c_str(key));
        return;
    }
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key), value);
}

void aws_json_add_aws_string_val(struct aws_json_value *data_json, const char *key, struct aws_string *value) {
    if (value == NULL || !aws_string_is_valid(value)) {
        aws_json_value_remove_from_object(data_json, aws_byte_cursor_from_c_str(key));
        return;
    }
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key),
                                 aws_json_value_new_string(get_iot_core_context()->alloc, aws_byte_cursor_from_string(value)));
}

void aws_json_add_aws_string_val1(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, struct aws_string *value) {
    if (value == NULL || !aws_string_is_valid(value)) {
        aws_json_value_remove_from_object(data_json, aws_byte_cursor_from_c_str(key));
        return;
    }
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key), aws_json_value_new_string(allocator, aws_byte_cursor_from_string(value)));
}

void aws_json_add_num_val(struct aws_json_value *data_json, const char *key, double value) {
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key),
                                 aws_json_value_new_number(get_iot_core_context()->alloc, value));
}

void aws_json_add_num_val1(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, double value) {
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key),
                                 aws_json_value_new_number(allocator, value));
}

void aws_json_add_bool_val(struct aws_json_value *data_json, const char *key, bool value) {
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key),
                                 aws_json_value_new_boolean(get_iot_core_context()->alloc, value));
}

void aws_json_add_bool_val1(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, bool value) {
    aws_json_value_add_to_object(data_json, aws_byte_cursor_from_c_str(key),
                                 aws_json_value_new_boolean(allocator, value));
}

void aws_json_add_array_element(struct aws_json_value* array, struct aws_json_value* value) {
    aws_json_value_add_array_element(array, value);
}

double aws_json_get_num_val(struct aws_json_value *data_json, const char *key) {
    struct aws_json_value *json_val = aws_json_value_get_from_object(data_json, aws_byte_cursor_from_c_str(key));
    double value;
    aws_json_value_get_number(json_val, &value);
    return value;

}

bool aws_json_get_bool_val(struct aws_json_value *data_json, const char *key) {
    struct aws_json_value *json_val = aws_json_value_get_from_object(data_json, aws_byte_cursor_from_c_str(key));
    bool value;
    aws_json_value_get_boolean(json_val, &value);
    return value;

}
/**
 * trim url 去除一些 无用字符
 * @param ch
 * @return
 */
bool url_trim(uint8_t ch) {
    if (ch < 32) {
        return true;
    }
    switch (ch) {
        case 0x20: /* ' ' - space */
        case 0x09: /* '\t' - horizontal tab */
        case 0x0A: /* '\n' - line feed */
        case 0x0B: /* '\v' - vertical tab */
        case 0x0C: /* '\f' - form feed */
        case 0x0D: /* '\r' - carriage return */
        case '\a': /* '\r' - carriage return */
            return true;
        default:
            return false;
    }
}


struct aws_string *md5File(FILE *file) {
    char input_buffer[1024] = {0};
    size_t input_size = 0;

    MD5_CTX ctx;
    MD5_Init(&ctx);

    while ((input_size = fread(input_buffer, 1, 1024, file)) > 0) {
        MD5_Update(&ctx, (uint8_t *) input_buffer, input_size);
    }
    uint8_t result[MD5_DIGEST_LENGTH];
    MD5_Final(result, &ctx);

    char mdt_str[32];
    AWS_ZERO_ARRAY(mdt_str);
    struct aws_byte_buf mdt_str_buf = aws_byte_buf_from_empty_array(mdt_str, sizeof(mdt_str));
    for (unsigned int i = 0; i < 16; ++i) {
        char str[3];
        sprintf(str, "%02x", result[i]);
        aws_byte_buf_write_from_whole_cursor(&mdt_str_buf, aws_byte_cursor_from_c_str(str));
    }
    struct aws_string *md5_string = aws_string_new_from_buf(get_iot_core_context()->alloc, &mdt_str_buf);
    return md5_string;
}

// gateway sha256
struct aws_string *hmac_sha256_encrypt(struct aws_allocator *allocator, int32_t random_num, uint64_t time_stamp, const char* device_name, const char* product_key, const char* product_secret) {;
    char inputStr[256];
    sprintf(inputStr, "device_name=%s&random_num=%d&product_key=%s&timestamp=%llu",
            device_name, random_num, product_key, time_stamp);
    struct aws_byte_cursor secretBuff = aws_byte_cursor_from_c_str(product_secret);
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


void common_hash_key_destroy(void *key) {
    struct aws_string *key_string = key;
    if (key_string && aws_string_is_valid(key_string)) {
        aws_string_destroy_secure(key_string);
    }
}


char *iot_get_common_topic(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name) {
    int32_t out_size = secure_strlen(fmt) + product_key->len + device_name->len;
    char *topic = (char*) aws_mem_calloc(allocator, 1, out_size + 1);
    sprintf(topic, fmt, aws_string_c_str(product_key), aws_string_c_str(device_name));
    return topic;
}

char *iot_get_topic_with_1_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, struct aws_string *p1) {
    int32_t out_size = secure_strlen(fmt) + product_key->len + device_name->len + p1->len;
    char *topic = aws_mem_calloc(allocator, 1, out_size + 1);
    sprintf(topic, fmt, aws_string_c_str(product_key), aws_string_c_str(device_name), aws_string_c_str(p1));
    return topic;
}


char *iot_get_topic_with_1_c_str_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, char *p1) {
    int32_t out_size = secure_strlen(fmt) + product_key->len + device_name->len + secure_strlen(p1);
    char *topic = aws_mem_calloc(allocator, 1, out_size + 1);
    sprintf(topic, fmt, aws_string_c_str(product_key), aws_string_c_str(device_name), p1);
    return topic;
}

char *iot_get_topic_with_2_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, struct aws_string *p1,
                                 struct aws_string *p2) {
    int32_t out_size = secure_strlen(fmt) + product_key->len + device_name->len + p1->len + p2->len;
    char *topic = aws_mem_calloc(allocator, 1, out_size + 1);
    sprintf(topic, fmt, aws_string_c_str(product_key), aws_string_c_str(device_name), aws_string_c_str(p1), aws_string_c_str(p2));
    return topic;
}

char *iot_get_topic_with_2_c_str_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, char *p1, char* p2) {
    int32_t out_size = secure_strlen(fmt) + product_key->len + device_name->len + secure_strlen(p1) + secure_strlen(p2);
    char *topic = aws_mem_calloc(allocator, 1, out_size + 1);
    sprintf(topic, fmt, aws_string_c_str(product_key), aws_string_c_str(device_name), p1, p2);
    return topic;
}

char *iot_get_topic_with_3_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, struct aws_string *p1,
                                 struct aws_string *p2, struct aws_string *p3) {
    return iot_get_topic_with_3_c_str_param(allocator, fmt, aws_string_c_str(product_key), aws_string_c_str(device_name),
                                     aws_string_c_str(p1), aws_string_c_str(p2), aws_string_c_str(p3));

}

char *iot_get_topic_with_3_c_str_param(struct aws_allocator *allocator, const char *fmt, const char* product_key, const char* device_name, const char* p1,
                                       const char* p2, const char* p3) {
    int32_t out_size = secure_strlen(fmt) + secure_strlen(product_key) + secure_strlen(device_name) + secure_strlen(p1) + secure_strlen(p2) + secure_strlen(p3);
    char *topic = aws_mem_calloc(allocator, 1, out_size + 1);
    sprintf(topic, fmt, (product_key), (device_name), (p1), (p2), (p3));
    return topic;
}

uint16_t str_to_uint16(const char* str) {
    if (str == NULL) {
        return 0;
    }
    int value = atoi(str);
    return (uint16_t)value;
}

char *get_file_name(struct aws_string path) {

}


int get_string_first_index(char *line, char c) {
    int i = 0;
    int len = strlen(line);
    for (i = 0; i < len; i++) {
        if (line[i] == c) {
            return i;
        }
    }
}


int get_string_index_by_times(char *line, char c, int32_t times) {
    int i = 0;
    int len = strlen(line);
    int find_time = 0;
    for (i = 0; i < len; i++) {
        if (line[i] == c) {
            find_time++;
            if (find_time == times) {
                return i;
            }
        }
    }
    return 0;
}

uint64_t aws_date_to_utc_time_mil(char *date_str) {
    struct aws_date_time date_time;
    struct aws_byte_buf date_buf = aws_byte_buf_from_c_str(date_str);
    aws_date_time_init_from_str(&date_time, &date_buf, AWS_DATE_FORMAT_AUTO_DETECT);
    uint64_t time = mktime(&date_time.gmt_time) * 1000;
    return time;
}


uint64_t aws_date_to_short_utc_time_mil(uint64_t time) {
    struct aws_date_time date_time;
    aws_date_time_init_epoch_millis(&date_time, time);

    uint8_t date_output[AWS_DATE_TIME_STR_MAX_LEN];
    AWS_ZERO_ARRAY(date_output);
    struct aws_byte_buf str_output = aws_byte_buf_from_array(date_output, sizeof(date_output));
    str_output.len = 0;
    aws_date_time_to_local_time_short_str(&date_time, AWS_DATE_FORMAT_ISO_8601, &str_output);
    return aws_date_to_utc_time_mil(date_output);
}

int32_t secure_strlen(const char *str) {
//    size_t len = 0;
//    aws_secure_strlen(str, 1024, &len);
//    return (int32_t) len;
    return strlen(str);
}

// url 解密
struct aws_string *aes_decode(struct aws_allocator *allocator, const char *device_secret, const char *encrypt_data) {
    struct aws_byte_cursor encoded_cur = aws_byte_cursor_from_c_str(encrypt_data);
    size_t decoded_length = 0;
    aws_base64_compute_decoded_len(&encoded_cur, &decoded_length);
    struct aws_byte_buf output_buf;
    aws_byte_buf_init(&output_buf, allocator, decoded_length + 1);
    aws_byte_buf_secure_zero(&output_buf);

    aws_base64_decode(&encoded_cur, &output_buf);

    AES_KEY aes_key;
    uint8_t aes_iv[16];
    char output[output_buf.len + 1];
    // iv  是密码的前16 位
    memset(output, 0, output_buf.len + 1);
    memcpy(aes_iv, device_secret, 16);
    AES_set_encrypt_key((uint8_t *) device_secret, 128, &aes_key);
    AES_cbc_encrypt(output_buf.buffer, (uint8_t *) output, output_buf.len, &aes_key, aes_iv, AES_DECRYPT);

    struct aws_byte_cursor decode_url_cur = aws_byte_cursor_from_c_str(output);
    struct aws_byte_cursor trim_url_cur = aws_byte_cursor_right_trim_pred(&decode_url_cur, url_trim);
    struct aws_string *decode_url = aws_string_new_from_cursor(allocator, &trim_url_cur);
    LOGD(TAG_IOT_UTIL, "aes_decode data = %s output_buf = %d,  len = %d", aws_string_c_str(decode_url), output_buf.len, strlen(output));
    aws_byte_buf_clean_up(&output_buf);
    return decode_url;
}


int str_start_with(const char *originString, char *prefix) {
    // 参数校验
    if (originString == NULL || prefix == NULL || strlen(prefix) > strlen(originString)) {
        return -1;
    }

    int n = strlen(prefix);
    int i;
    for (i = 0; i < n; i++) {
        if (originString[i] != prefix[i]) {
            return 1;
        }
    }
    return 0;
}

int str_end_with(const char *originString, char *end) {
    // 参数校验
    if (originString == NULL || end == NULL || strlen(end) > strlen(originString)) {
        return -1;
    }

    int n = strlen(end);
    int m = strlen(originString);
    int i;
    for (i = 0; i < n; i++) {
        if (originString[m - i - 1] != end[n - i - 1]) {
            return 1;
        }
    }
    return 0;
}

struct aws_string* get_user_name(struct aws_allocator * allocator, struct aws_string* product_key, struct aws_string* device_name) {
    const char* use_name_c_str =  get_user_name_c_str_param(allocator, aws_string_c_str(product_key), aws_string_c_str(device_name));
    struct aws_string* use_name = aws_string_new_from_c_str(allocator, use_name_c_str);
    aws_mem_release(allocator, use_name_c_str);
    return use_name;
}

const char* get_user_name_c_str_param(struct aws_allocator * allocator, const char* product_key, const char* device_name) {
    int length = strlen(product_key) + strlen(device_name) + 10;
    char* username = (char*) aws_mem_acquire(allocator, length);
    sprintf(username, "%s|%s", aws_string_c_str(product_key), aws_string_c_str(device_name));
    return username;
}

