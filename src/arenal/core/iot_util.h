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

#ifndef ARENAL_IOT_IOT_UTIL_H
#define ARENAL_IOT_IOT_UTIL_H

#include <aws/common/string.h>


int32_t arenal_get_random_num();


char *aws_cur_to_char_str(
        struct aws_allocator *allocator,
        const struct aws_byte_cursor *cur);

struct aws_string *get_uuid(struct aws_allocator *allocator);

const char* get_uuid_c_str(struct aws_allocator* allocator);

char *aws_buf_to_char_str(
        struct aws_allocator *allocator,
        const struct aws_byte_buf *cur);


char *aws_string_new_char_str(
        struct aws_allocator *allocator,
        const struct aws_string *cur);

char *get_random_string_with_time_suffix(struct aws_allocator *allocator);

struct aws_string *get_random_string_id(struct aws_allocator *allocator);

const char* get_random_string_id_c_str(struct aws_allocator* allocator);

int get_random_num_uint64(uint64_t* out);

int get_random_num_uint32(uint32_t* out);

uint64_t get_current_time_mil();

uint64_t get_current_time_sec();

struct aws_string *get_date_format_iso_8601_data_str(struct aws_allocator *allocator);

struct aws_string *
format_unique_fieldname(struct aws_allocator *allocator, const char *moduleKey, const char *identifier);


struct aws_json_value *
new_reply_payload(struct aws_allocator *alloc, struct aws_byte_cursor idCur, int code, struct aws_json_value *data);

struct aws_json_value *
new_request_payload(struct aws_allocator *alloc, const char *version,
                    struct aws_json_value *data);

struct aws_string *aws_json_get_string_val(struct aws_json_value *data_json, const char *key);

struct aws_string *aws_json_get_string1_val(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key);

struct aws_byte_cursor aws_json_get_str_byte_cur_val(struct aws_json_value *data_json, const char *key);

struct aws_byte_buf aws_json_get_json_obj_to_bye_buf(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key);

struct aws_json_value* aws_json_get_json_obj(struct  aws_allocator* allocator, struct aws_json_value* data_json, const char* key);

struct aws_byte_buf aws_json_obj_to_bye_buf(struct aws_allocator *allocator, struct aws_json_value *data_json);


char *aws_json_get_str(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key);

void aws_json_add_str_val_1(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, const char *value);

void aws_json_add_json_str_obj(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, const char *value);

void aws_json_add_json_obj(struct aws_json_value *data_json, const char *key, struct aws_json_value *value);

void aws_json_add_str_val(struct aws_json_value *data_json, const char *key, const char *value);

void aws_json_add_aws_string_val(struct aws_json_value *data_json, const char *key, struct aws_string *value);

void aws_json_add_aws_string_val1(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, struct aws_string *value);

void aws_json_add_num_val(struct aws_json_value *data_json, const char *key, double value);

void aws_json_add_num_val1(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, double value);

void aws_json_add_bool_val(struct aws_json_value *data_json, const char *key, bool value);

void aws_json_add_bool_val1(struct aws_allocator *allocator, struct aws_json_value *data_json, const char *key, bool value);

void aws_json_add_array_element(struct aws_json_value* data_json, struct aws_json_value* array);

double aws_json_get_num_val(struct aws_json_value *data_json, const char *key);

bool aws_json_get_bool_val(struct aws_json_value *data_json, const char *key);

bool url_trim(uint8_t ch);

struct aws_string *md5File(FILE *file);

struct aws_string *hmac_sha256_encrypt(struct aws_allocator *allocator, int32_t random_num, uint64_t time_stamp, const char* device_name, const char* product_key, const char* product_secret);

int32_t secure_strlen(const char *str);

void common_hash_key_destroy(void *key);


char *iot_get_common_topic(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name);

char *iot_get_topic_with_1_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, struct aws_string *p1);

char *iot_get_topic_with_1_c_str_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, char *p1);

char *iot_get_topic_with_2_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, struct aws_string *p1,
                                 struct aws_string *p2);

char *iot_get_topic_with_2_c_str_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, char *p1, char* p2);

char *iot_get_topic_with_3_param(struct aws_allocator *allocator, char *fmt, struct aws_string *product_key, struct aws_string *device_name, struct aws_string *p1,
                                 struct aws_string *p2, struct aws_string *p3);

char *iot_get_topic_with_3_c_str_param(struct aws_allocator *allocator, const char *fmt, const char* product_key, const char* device_name, const char* p1,
                                 const char* p2, const char* p3);

uint16_t str_to_uint16(const char* str);

char *get_file_name(struct aws_string path);


int get_string_first_index(char *line, char c);


int get_string_index_by_times(char *line, char c, int32_t times);

uint64_t aws_date_to_utc_time_mil(char *line);

uint64_t aws_date_to_short_utc_time_mil(uint64_t time);

struct aws_string *aes_decode(struct aws_allocator *allocator, const char *device_secret, const char *encrypt_data);

int str_start_with(const char *originString, char *prefix);

int str_end_with(const char *originString, char *end);

struct aws_string* get_user_name(struct aws_allocator * allocator, struct aws_string* product_key, struct aws_string* device_name);

#endif //ARENAL_IOT_IOT_UTIL_H
