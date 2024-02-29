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

#ifndef ARENAL_IOT_IOT_CODE_H
#define ARENAL_IOT_IOT_CODE_H

/** start common error code **/
/**
 *  API执行成功
 */
#define CODE_SUCCESS     (0x0000)


/**
 * 用户输入参数中包含非法的空指针
 */
#define CODE_USER_INPUT_NULL_POINTER   -101

/**
 * 用户输入超出范围
 */
#define CODE_USER_INPUT_OUT_RANGE     -101
/** end common error code **/


/** start http error code **/
/**
 *  http 请求 url 错误
 */
#define CODE_HTTP_URL_INVALID  -201

/**
 * url 转 uri 失败
 */
#define CODE_HTTP_URL_PARSE_ERROR -202

/**
 * http 请求建立失败
 */
#define CODE_HTTP_CLIENT_CONNECT_ERROR -203

/**
 * 当前正在请求, 请求重复了, 请勿重复调用 iot_http_request 函数
 */
#define CODE_HTTP_REQUEST_REPETITION -204

/**
 * http 内部错误 stram 未空
 */
#define CODE_HTTP_REQUEST_STREAM_NULL -205

/** end http error code **/


/** start mqtt error code **/
/**
 * mqtt 断开链接失败
 */
#define CODE_MQTT_DISCONNECT_FAILED -301

/**
 * 设备信息无效,product_key  device_name  device_secret 未赋值
 */
#define CODE_MQTT_CONNECT_DEVICE_INFO_INVALID -302

/**
 * mqtt  域名无效
 */
#define CODE_MQTT_CONNECT_HOST_INVALID -303

/**
 * mqtt 端口无效
 */
#define CODE_MQTT_CONNECT_PORT_INVALID -304

/**
 * mqtt 内部错误
 */
#define CODE_MQTT_CONNECT_AWS_INNER_ERROR -305

#define CODE_MQTT_CONNECT_DYNAMIC_REGISTER_REQUEST_ERROR -305
/** end mqtt error code **/


/** start things model error code **/
#define STATE_DM_MQTT_HANDLE_IS_NULL -306
#define STATE_DM_MQTT_PUBLISH_ERROR -307
#define STATE_DM_MQTT_PUBLISH_TYPE_ERROR  -308
/** end things model error code **/

/** start ota http download error code **/
#define HTTP_DOWNLOAD_FILE_WRITE_ERROR -401
#define HTTP_DOWNLOAD_FILE_CREAT_ERROR -402
#define HTTP_DOWNLOAD_DIR_CREAT_ERROR -403
#define HTTP_DOWNLOAD_HEADER_REQUEST -404
#define HTTP_DOWNLOAD_DOWNLOAD_DIR_OR_PATH_NULL -405
#define HTTP_DOWNLOAD_DOWNLOAD_BEFORE_FAILED -406
#define HTTP_DOWNLOAD_DOWNLOAD_UNKNOWN_FILE_SIZE -407
/** end http error code **/


/** start ota error code **/
#define OTA_DOWNLOAD_FILE_SIZE_ERROR -501
#define OTA_DOWNLOAD_FILE_EMPTY_ERROR -502
#define OTA_DOWNLOAD_FILE_SIGN_CHECK_ERROR -503
#define OTA_DEVICE_INFO_NOT_SET -504
#define OTA_INSTALL_FAILED -505
/** end ota error code **/


#endif //ARENAL_IOT_IOT_CODE_H
