#
# Copyright 2022-2024 Beijing Volcano Engine Technology Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
cmake_minimum_required(VERSION 3.10)

project(arenal_iot_lib VERSION 0.1 LANGUAGES C)


file(GLOB_RECURSE TEST_SOURCE "tests/*.c")
file(GLOB_RECURSE CORE_SOURCE "core/*.c")
file(GLOB_RECURSE CORE_HEADER "core/*.h")
file(GLOB_RECURSE THINGS_MODEL_SOURCE "thing_model/*.c")
file(GLOB_RECURSE THINGS_MODEL_HEADER "thing_model/*.h")

file(GLOB_RECURSE LOG_SOURCE "log/*.c")
file(GLOB_RECURSE LOG_HEADER "log/*.h")

file(GLOB_RECURSE OTA_SOURCE "ota/*.c")
file(GLOB_RECURSE OTA_HEADER "ota/*.h")


# 获取当前 git commonId 写入到 c 文件中
include(GetGitRevisionDescription)
get_git_head_revision(GIT_REFSPEC GIT_SHA1)
add_definitions("-DGIT_SHA1=${GIT_SHA1}")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/core/GitSHA1.c.in" "${CMAKE_CURRENT_BINARY_DIR}/core/GitSHA1.c" @ONLY)
list(APPEND SOURCE "${CMAKE_CURRENT_BINARY_DIR}/core/GitSHA1.c" core/GitSHA1.h)

set(IOT_SOURCES
        ${CORE_SOURCE} ${CORE_HEADER}
        ${THINGS_MODEL_SOURCE} ${THINGS_MODEL_HEADER}
        ${LOG_SOURCE} ${LOG_HEADER}
        ${OTA_SOURCE} ${OTA_HEADER}
        )

find_package(aws-c-cal)
find_package(aws-c-io)
find_package(aws-c-compression)
find_package(aws-c-mqtt)
find_package(aws-c-http)
find_package(aws-c-common)
find_package(s2n)
find_package(crypto)
#依赖的库
set(IOT_LINKS
        AWS::aws-c-cal
        AWS::aws-c-io
        AWS::aws-c-compression
        AWS::aws-c-mqtt
        AWS::aws-c-http
        AWS::aws-c-common
        AWS::s2n
        )

#依赖库的头文件
set(IOT_INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}
        ${AWS_INCLUDES}
        )

# 动态库
add_library(iot_sdk_shared
        SHARED
        ${IOT_SOURCES}
        )
target_link_libraries(iot_sdk_shared
        ${IOT_LINKS}
        )
target_include_directories(iot_sdk_shared PUBLIC
        ${IOT_INCLUDES}
        )


# 静态库
add_library(iot_sdk_static
        STATIC
        ${IOT_SOURCES}
        )

target_link_libraries(iot_sdk_static
        ${IOT_LINKS}
        )

target_include_directories(iot_sdk_static PUBLIC
        ${IOT_INCLUDES}
        )
