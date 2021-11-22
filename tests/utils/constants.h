/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2021-09-16
 * Description: provide cni api functions
 */
#ifndef _TESTS_CONSTANTS_H
#define _TESTS_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_CNI_BIN_PATH "/opt/cni/bin"

#define COMMON_CONF_LIST "{\"cniVersion\":\"0.3.0\",\"name\":\"default\", \
     \"plugins\":[{\"cniVersion\":\"0.3.0\", \"name\":\"default\",\"type\":\"bridge\"}, \
     {\"name\": \"exist\",\"type\": \"bridge\", \"dns\": {\"nameservers\": [\"10.1.0.1\"]}}]}"

#define CONF_LIST_WITH_PORTMAP "{\"cniVersion\":\"0.3.0\",\"name\":\"default\", \
     \"plugins\":[{\"cniVersion\":\"0.3.0\", \"name\":\"default\",\"type\":\"bridge\"}, \
     {\"type\": \"portmap\", \"capabilities\": { \"portMappings\": true } }]}"

#define COMMON_CONF "{\"cniVersion\":\"0.3.0\",\"name\":\"default\", \
     \"type\": \"bridge\", \"bridge\": \"cni0\", \"isGateway\": \"true\", \
     \"ipam\": {\"type\": \"host-local\", \"subnet\": \"10.1.0.0/16\", \"gateway\": \"10.1.0.1\"},\
     \"dns\": {\"nameservers\": [\"10.1.0.1\"]}}"


#define INVALID_COMMON_CONF_LIST "{\"cniVersion\":\"0.3.0\",\"name\":\"default\", \
     \"plugins\":[{\"cniVersion\":\"0.3.0\", \"name\":\"default\",\"type\":\"bridge\"}, \
     {\"name\": \"exist\",\"type\": \"xxxx\", \"dns\": {\"nameservers\": [\"10.1.0.1\"]}}]}"

#define INVALID_COMMON_CONF "{\"cniVersion\":\"0.3.0\",\"name\":\"default\", \
     \"type\": \"xxxx\", \"bridge\": \"cni0\", \"isGateway\": \"true\", \
     \"ipam\": {\"type\": \"host-local\", \"subnet\": \"10.1.0.0/16\", \"gateway\": \"10.1.0.1\"},\
     \"dns\": {\"nameservers\": [\"10.1.0.1\"]}}"


#define BAD_COMMON_CONF_LIST "{\"cniVersion\":\"0.3.0\",\"name\":\"default\", \
     \"plugins\":[{\"cniVersion\":\"0.3.0\", \"name\":\"default\",\"type\":\"bridge-bad\"}, \
     {\"name\": \"exist\",\"type\": \"bridge\", \"dns\": {\"nameservers\": [\"10.1.0.1\"]}}]}"

#ifdef __cplusplus
}
#endif

#endif
