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
#include <gtest/gtest.h>

#include <iostream>

#include <string.h>
#include <unistd.h>

#include "api.h"
#include "version.h"
#include "conf.h"
#include "constants.h"


void api_check_network_config_list(struct cni_network_list_conf *conf, const char *target_name, bool check_plugin_name)
{
    /* check network_config_list */
    ASSERT_NE(conf, nullptr);
    ASSERT_NE(conf->first_plugin_name, nullptr);
    ASSERT_NE(conf->first_plugin_type, nullptr);
    EXPECT_STREQ(target_name, conf->name);
    ASSERT_NE(conf->bytes, nullptr);

    struct network_config_list *tmp = NULL;
    char *err = NULL;
    int ret = conflist_from_bytes(conf->bytes, &tmp, &err);
    if (ret != 0) {
        std::cout << "conflist parse failed:" << err << std::endl;
    }
    free(err);
    ASSERT_EQ(ret , 0);

    /* check net_conf_list */
    EXPECT_STREQ("0.3.0", tmp->list->cni_version);
    EXPECT_STREQ(target_name, tmp->list->name);
    ASSERT_NE(tmp->list->plugins, nullptr);
    ASSERT_EQ(tmp->list->plugins_len, 2);
    EXPECT_STREQ("0.3.0", tmp->list->plugins[0]->cni_version);
    if (check_plugin_name) {
        EXPECT_STREQ(target_name, tmp->list->plugins[0]->name);
    }
    EXPECT_STREQ("bridge", tmp->list->plugins[0]->type);
    ASSERT_EQ(tmp->list->plugins[0]->dns, nullptr);
    ASSERT_EQ(tmp->list->plugins[0]->runtime_config, nullptr);
    ASSERT_EQ(tmp->list->plugins[0]->capabilities, nullptr);
    ASSERT_EQ(tmp->list->plugins[0]->prev_result, nullptr);
    EXPECT_STREQ("10.1.0.1", tmp->list->plugins[1]->dns->nameservers[0]);
    EXPECT_STREQ("bridge", tmp->list->plugins[1]->type);

    free_network_config_list(tmp);
}

TEST(api_testcases, cni_conflist_from_bytes)
{
    int ret;
    struct cni_network_list_conf *new_list = NULL;
    char *err = NULL;

    ret = cni_conflist_from_bytes(COMMON_CONF_LIST, &new_list, &err);
    if (ret != 0) {
        std::cout << "conflist parse failed:" << err << std::endl;
    }
    free(err);
    std::cout << new_list->bytes << std::endl;

    api_check_network_config_list(new_list, "default", true);

    free(err);
    free_cni_network_list_conf(new_list);
}

void api_check_network_config_list_from_conf(struct cni_network_list_conf *conf, const char *target_name, bool check_plugin_name)
{
    /* check network_config_list */
    ASSERT_NE(conf, nullptr);
    ASSERT_NE(conf->first_plugin_name, nullptr);
    ASSERT_NE(conf->first_plugin_type, nullptr);
    EXPECT_STREQ(target_name, conf->name);
    ASSERT_NE(conf->bytes, nullptr);

    struct network_config_list *tmp = NULL;
    char *err = NULL;
    int ret = conflist_from_bytes(conf->bytes, &tmp, &err);
    if (ret != 0) {
        std::cout << "conflist parse failed:" << err << std::endl;
    }
    free(err);
    ASSERT_EQ(ret , 0);

    /* check net_conf_list */
    EXPECT_STREQ("0.3.0", tmp->list->cni_version);
    EXPECT_STREQ(target_name, tmp->list->name);
    ASSERT_NE(tmp->list->plugins, nullptr);
    ASSERT_EQ(tmp->list->plugins_len, 1);
    EXPECT_STREQ("0.3.0", tmp->list->plugins[0]->cni_version);
    if (check_plugin_name) {
        EXPECT_STREQ(target_name, tmp->list->plugins[0]->name);
    }
    EXPECT_STREQ("bridge", tmp->list->plugins[0]->type);
    ASSERT_NE(tmp->list->plugins[0]->dns, nullptr);
    EXPECT_STREQ("10.1.0.1", tmp->list->plugins[0]->dns->nameservers[0]);
    EXPECT_STREQ("bridge", tmp->list->plugins[0]->type);
    ASSERT_EQ(tmp->list->plugins[0]->runtime_config, nullptr);
    ASSERT_EQ(tmp->list->plugins[0]->capabilities, nullptr);
    ASSERT_EQ(tmp->list->plugins[0]->prev_result, nullptr);
    ASSERT_NE(tmp->list->plugins[0]->ipam, nullptr);
    EXPECT_STREQ("host-local", tmp->list->plugins[0]->ipam->type);
    EXPECT_STREQ("10.1.0.0/16", tmp->list->plugins[0]->ipam->subnet);
    EXPECT_STREQ("10.1.0.1", tmp->list->plugins[0]->ipam->gateway);

    free_network_config_list(tmp);
}

TEST(api_testcases, cni_conflist_from_conf)
{
    int ret;
    struct cni_network_list_conf *new_list = NULL;
    char *err = NULL;
    struct cni_network_conf test = {
        .name = "default",
        .type = "bridge",
        .bytes = COMMON_CONF,
    };

    ret = cni_conflist_from_conf(&test, &new_list, &err);
    if (ret != 0) {
        std::cout << "conflist parse failed:" << err << std::endl;
    }
    free(err);
    std::cout << new_list->bytes << std::endl;

    api_check_network_config_list_from_conf(new_list, "default", true);

    free(err);
    free_cni_network_list_conf(new_list);
}

TEST(api_testcases, get_version_info)
{
    const std::string CNI_PLUGIN_PATH = "/opt/cni/bin/";
    char *err = nullptr;
    struct plugin_info *pinfo = nullptr;
    size_t i = 0;
    int ret = 0;
    char *paths[] = {strdup(CNI_PLUGIN_PATH.c_str()), nullptr};
    const std::string bridge_name = "bridge";

    ret = cni_get_version_info(bridge_name.c_str(), paths, &pinfo, &err);
    if (ret != 0) {
        if (strstr(err, "No such file or directory") != nullptr) {
            std::cout << "Skip: cni_get_version_info api cause by no bridge plugin found" << std::endl;
            return;
        }
        std::cout << "Get version failed:" << err << std::endl;
    }
    ASSERT_EQ(ret, 0);

    /* check plugin info */
    EXPECT_STREQ("0.4.0", pinfo->cniversion);
    ASSERT_LE(0, pinfo->supported_versions_len);
    for (i = 0; i < pinfo->supported_versions_len; i++) {
        if (strcmp(pinfo->supported_versions[i], CURRENT_VERSION) == 0) {
            break;
        }
    }
    ASSERT_LE(i, pinfo->supported_versions_len);

    free_plugin_info(pinfo);
    free(paths[0]);
    paths[0] = nullptr;
}

