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

#ifndef ARENAL_IOT_IOT_CORE_H
#define ARENAL_IOT_IOT_CORE_H

#include <stdio.h>
#include <stdint.h>
#include "iot_code.h"

typedef struct core_context core_context_t;

void iot_core_init();

core_context_t *get_iot_core_context(void);

void iot_core_de_init();

#endif //ARENAL_IOT_IOT_CORE_H
