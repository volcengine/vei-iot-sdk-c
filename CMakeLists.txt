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

project(arenal_iot VERSION 1.0)

set(CMAKE_C_STANDARD 99)


option(BUILD_EXAMPLES "build examples" off)
option(BUILD_WITH_AWS "build with aws" off)
option(BUILD_SHARED_LIBS "build shared libs" off)

IF (APPLE)
    set(CMAKE_THREAD_LIBS_INIT "-lpthread")
    set(CMAKE_HAVE_THREADS_LIBRARY 1)
    set(CMAKE_USE_WIN32_THREADS_INIT 0)
    set(CMAKE_USE_PTHREADS_INIT 1)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
ENDIF ()

get_filename_component(__root_dir "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
set(ROOT_DIR ${__root_dir} CACHE INTERNAL "C SDK source root.")
set(SRC_DIR "${ROOT_DIR}/src" CACHE INTERNAL "src libraries root.")
set(SRC_IOT_DIR "${ROOT_DIR}/src/arenal" CACHE INTERNAL "src iot libraries root.")
set(MODULES_DIR "${ROOT_DIR}/libraries" CACHE INTERNAL "C SDK modules root.")
set(3RDPARTY_DIR "${MODULES_DIR}/3rdparty" CACHE INTERNAL "3rdparty libraries root.")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${MODULES_DIR}/3rdparty_build/lib/cmake)
list(APPEND CMAKE_PREFIX_PATH ${MODULES_DIR}/3rdparty_build/)
set(AWS_INCLUDES ${MODULES_DIR}/3rdparty_build/include/)
set(AWS_LIBS ${MODULES_DIR}/3rdparty_build/lib/)


message("CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")
message("CMAKE_INSTALL_LIBDIR = ${CMAKE_INSTALL_LIBDIR}")
message("find_path = ${find_path}")
message("CMAKE_PREFIX_PATH = ${CMAKE_PREFIX_PATH}")

add_subdirectory(src)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
ENDIF()
