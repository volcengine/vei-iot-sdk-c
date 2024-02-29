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
project(IoTSDKSamples C)

set(CMAKE_C_STANDARD 99)

set(LOG_DIR "./log")
configure_file("iot/test_prams.c.in" "${CMAKE_CURRENT_BINARY_DIR}/test_prams.c" @ONLY)

include_directories("include")
link_directories(lib)

IF (APPLE)
    IF (BUILD_SHARED_LIBS)
        set(IOT_LINKS
                libaws-c-cal.1.0.0.dylib
                libaws-c-cal.dylib
                libaws-c-common.1.0.0.dylib
                libaws-c-common.1.dylib
                libaws-c-common.dylib
                libaws-c-compression.1.0.0.dylib
                libaws-c-compression.dylib
                libaws-c-http.1.0.0.dylib
                libaws-c-http.dylib
                libaws-c-io.1.0.0.dylib
                libaws-c-io.dylib
                libaws-c-mqtt.1.0.0.dylib
                libaws-c-mqtt.dylib
                libcrypto.dylib
                libiot_sdk_shared.dylib
                libs2n.1.0.0.dylib
                libs2n.1.dylib
                libs2n.dylib
                libssl.dylib
        )
    ELSE ()
        set(IOT_LINKS
                libbyteiot.a
                "-framework Security -framework CoreFoundation"
        )
    ENDIF ()
ELSEIF (UNIX AND NOT APPLE)
    IF (BUILD_SHARED_LIBS)
        set(IOT_LINKS
                libaws-c-cal.so.1.0.0
                libaws-c-cal.so
                libaws-c-common.so.1.0.0
                libaws-c-common.so.1
                libaws-c-common.so
                libaws-c-compression.so.1.0.0
                libaws-c-compression.so
                libaws-c-http.so.1.0.0
                libaws-c-http.so
                libaws-c-io.so.1.0.0
                libaws-c-io.so
                libaws-c-mqtt.so.1.0.0
                libaws-c-mqtt.so
                libcrypto.so
                libiot_sdk_shared.so
                libs2n.so.1.0.0
                libs2n.so.1
                libs2n.so
                libssl.so
        )
    ELSE ()
        set(IOT_LINKS
                libbyteiot.a
                "-lpthread -ldl -lm"
        )
    ENDIF ()
ENDIF ()

add_executable(demo_temp_humid use/demo_temp_humid.c)
target_link_libraries(demo_temp_humid
        ${IOT_LINKS}
)

set(TEST_COMMON_SOURCE
        ${CMAKE_CURRENT_BINARY_DIR}/test_prams.c
        iot/test_params.h
)

include_directories(iot)

add_executable(test_tm_event iot/test_tm_event.c ${TEST_COMMON_SOURCE})
target_link_libraries(test_tm_event
        ${IOT_LINKS}
)

add_executable(test_tm_property iot/test_tm_property.c ${TEST_COMMON_SOURCE})
target_link_libraries(test_tm_property
        ${IOT_LINKS}
)

add_executable(test_tm_property_set iot/test_tm_property_set.c ${TEST_COMMON_SOURCE})
target_link_libraries(test_tm_property_set
        ${IOT_LINKS}
)

add_executable(test_tm_service iot/test_tm_service.c ${TEST_COMMON_SOURCE})
target_link_libraries(test_tm_service
        ${IOT_LINKS}
)

add_executable(test_tm_custom_topic iot/test_tm_custom_topic.c ${TEST_COMMON_SOURCE})
target_link_libraries(test_tm_custom_topic
        ${IOT_LINKS}
)
