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
#include <dirent.h>

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
        .name = (char *)"default",
        .type = (char *)"bridge",
        .bytes = (char *)COMMON_CONF,
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
    char pwd_buf[PATH_MAX] = {0X0};
    char *pwd = nullptr;

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);

    pwd = strcat(pwd_buf, "/utils");
    ASSERT_NE(pwd, nullptr);

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
            ret = 0;
        }
        std::cout << "Get version failed:" << err << std::endl;
    }
    ASSERT_EQ(ret, 0);
    free(err);
    err = nullptr;

    free(paths[0]);
    paths[0] = strdup(pwd_buf);
    ret = cni_get_version_info(bridge_name.c_str(), paths, &pinfo, &err);
    if (ret != 0) {
        std::cout << "Get version failed:" << err << std::endl;
    } 
    ASSERT_EQ(ret, 0);

    /* check plugin info */
    EXPECT_STREQ("0.3.1", pinfo->cniversion);
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

TEST(api_testcases, cni_log_ops)
{
    int ret = 0;

    ret = cni_log_init("xxx", "/tmp/cni.log", "debug");
    ASSERT_NE(ret, 0);
    ret = cni_log_init("file", "xxx", "debug");
    ASSERT_NE(ret, 0);
    ret = cni_log_init("file", "/tmp/cni.log", "xxx");
    ASSERT_NE(ret, 0);

    ret = cni_log_init("stdout", nullptr, "debug");
    ASSERT_EQ(ret, 0);

    cni_set_log_prefix("xxx");

    cni_free_log_prefix();
}

TEST(api_testcases, cni_add_network_list)
{
    int ret = 0;
    char pwd_buf[PATH_MAX] = {0X0};
    char *pwd = nullptr;
    char *paths[] = {pwd_buf, nullptr};
    pid_t cpid = getpid();
    char netns[PATH_MAX] = {0x0};
    char *err = NULL;
    struct runtime_conf rc = {
        .container_id = (char *)"abcd",
        .netns = netns,
        .ifname = (char *)"eth0",
        .p_mapping_len = 1,
    };
    struct result *pret = nullptr;

    rc.p_mapping = (struct cni_port_mapping **)calloc(1, sizeof(struct cni_port_mapping *));
    ASSERT_NE(rc.p_mapping, nullptr);
    rc.p_mapping[0] = (struct cni_port_mapping *)calloc(1, sizeof(struct cni_port_mapping));
    ASSERT_NE(rc.p_mapping[0], nullptr);
    rc.p_mapping[0]->container_port = 80;
    rc.p_mapping[0]->host_port = 8080;

    (void)sprintf(netns, "/proc/%d/ns/net", cpid);

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);

    pwd = strcat(pwd_buf, "/utils");
    ASSERT_NE(pwd, nullptr);

    std::cout << "cni bin path: " << pwd_buf << std::endl;

    ret = cni_add_network_list(COMMON_CONF_LIST, &rc, paths, &pret, &err);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(err, nullptr);
    free_result(pret);
    pret = nullptr;

    std::cout << "cni bin path with cap: " << pwd_buf << std::endl;
    ret = cni_add_network_list(CONF_LIST_WITH_PORTMAP, &rc, paths, &pret, &err);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(err, nullptr);
    free_result(pret);
    pret = nullptr;

    std::cout << "invlaid config list" << std::endl;
    ret = cni_add_network_list(INVALID_COMMON_CONF_LIST, &rc, paths, &pret, &err);
    ASSERT_NE(ret, 0);
    free_result(pret);
    pret = nullptr;
    free(err);
    err = nullptr;

    std::cout << "bad config list" << std::endl;
    ret = cni_add_network_list(BAD_COMMON_CONF_LIST, &rc, paths, &pret, &err);
    ASSERT_NE(ret, 0);
    free_result(pret);
    pret = nullptr;

    free(err);
}

TEST(api_testcases, cni_add_network)
{
    int ret = 0;
    char pwd_buf[PATH_MAX] = {0X0};
    char *pwd = nullptr;
    char *paths[] = {pwd_buf, nullptr};
    pid_t cpid = getpid();
    char netns[PATH_MAX] = {0x0};
    char *err = NULL;
    struct runtime_conf rc = {
        .container_id = (char *)"abcd",
        .netns = netns,
        .ifname = (char *)"eth0",
        .p_mapping_len = 1,
    };
    struct result *pret = nullptr;

    rc.p_mapping = (struct cni_port_mapping **)calloc(1, sizeof(struct cni_port_mapping *));
    ASSERT_NE(rc.p_mapping, nullptr);
    rc.p_mapping[0] = (struct cni_port_mapping *)calloc(1, sizeof(struct cni_port_mapping));
    ASSERT_NE(rc.p_mapping[0], nullptr);
    rc.p_mapping[0]->container_port = 80;
    rc.p_mapping[0]->host_port = 8080;

    (void)sprintf(netns, "/proc/%d/ns/net", cpid);

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);

    pwd = strcat(pwd_buf, "/utils");
    ASSERT_NE(pwd, nullptr);

    std::cout << "cni bin path: " << pwd_buf << std::endl;

    ret = cni_add_network(COMMON_CONF, &rc, paths, &pret, &err);
    ASSERT_EQ(ret, 0);
    free_result(pret);
    pret = nullptr;

    ret = cni_add_network(INVALID_COMMON_CONF, &rc, paths, &pret, &err);
    ASSERT_NE(ret, 0);
    free_result(pret);
    pret = nullptr;

    free(err);
}

TEST(api_testcases, cni_delete_network_list)
{
    int ret = 0;
    char pwd_buf[PATH_MAX] = {0X0};
    char *pwd = nullptr;
    char *paths[] = {pwd_buf, nullptr};
    pid_t cpid = getpid();
    char netns[PATH_MAX] = {0x0};
    char *err = NULL;
    struct runtime_conf rc = {
        .container_id = (char *)"abcd",
        .netns = netns,
        .ifname = (char *)"eth0",
    };

    (void)sprintf(netns, "/proc/%d/ns/net", cpid);

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);

    pwd = strcat(pwd_buf, "/utils");
    ASSERT_NE(pwd, nullptr);

    std::cout << "cni bin path: " << pwd_buf << std::endl;

    ret = cni_del_network_list(COMMON_CONF_LIST, &rc, paths, &err);
    ASSERT_EQ(ret, 0);

    std::cout << "delete with invlaid config list" << std::endl;
    ret = cni_del_network_list(INVALID_COMMON_CONF_LIST, &rc, paths, &err);
    ASSERT_NE(ret, 0);
    free(err);
    err = nullptr;

    std::cout << "delete with bad config list" << std::endl;
    ret = cni_del_network_list(BAD_COMMON_CONF_LIST, &rc, paths, &err);
    ASSERT_NE(ret, 0);

    free(err);
}

TEST(api_testcases, cni_delete_network)
{
    int ret = 0;
    char pwd_buf[PATH_MAX] = {0X0};
    char *pwd = nullptr;
    char *paths[] = {pwd_buf, nullptr};
    pid_t cpid = getpid();
    char netns[PATH_MAX] = {0x0};
    char *err = NULL;
    struct runtime_conf rc = {
        .container_id = (char *)"abcd",
        .netns = netns,
        .ifname = (char *)"eth0",
    };

    (void)sprintf(netns, "/proc/%d/ns/net", cpid);

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);

    pwd = strcat(pwd_buf, "/utils");
    ASSERT_NE(pwd, nullptr);

    std::cout << "cni bin path: " << pwd_buf << std::endl;

    ret = cni_del_network(COMMON_CONF, &rc, paths, &err);
    ASSERT_EQ(ret, 0);

    ret = cni_del_network(INVALID_COMMON_CONF, &rc, paths, &err);
    ASSERT_NE(ret, 0);

    free(err);
}

TEST(api_testcases, cni_conf_files)
{
    int ret = 0;
    char pwd_buf[PATH_MAX] = {0X0};
    char *pwd = nullptr;
    char *paths[] = {pwd_buf, nullptr};
    char *err = NULL;
    const char *exts[] = {"json", "conf", "conflist"};
    char **result = nullptr;

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);

    pwd = strcat(pwd_buf, "/confs");
    ASSERT_NE(pwd, nullptr);

    std::cout << "cni conf path: " << pwd_buf << std::endl;

    ret = cni_conf_files(pwd_buf, exts, 3, &result, &err);
    ASSERT_EQ(ret, 0);
    free(err);
    err = nullptr;

    ret = cni_conf_files("xxxx", exts, 3, &result, &err);
    ASSERT_EQ(ret, 0);
    free(err);
    err = nullptr;

    ret = cni_conf_files(pwd_buf, exts, 3, &result, nullptr);
    ASSERT_NE(ret, 0);

    free(err);
}

TEST(api_testcases, cni_conf_from_file)
{
    int ret = 0;
    char pwd_buf[PATH_MAX] = {0X0};
    char *pwd = nullptr;
    char *err = NULL;
    struct cni_network_conf *config = nullptr;

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);
    pwd = strcat(pwd_buf, "/confs/default-invalid.conf");
    ASSERT_NE(pwd, nullptr);
    std::cout << "cni conf path: " << pwd_buf << std::endl;
    ret = cni_conf_from_file(pwd_buf, &config, &err);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(config, nullptr);
    free(err);
    err = nullptr;
    free_cni_network_conf(config);
    config = nullptr;
    memset(pwd_buf, 0, PATH_MAX);

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);
    pwd = strcat(pwd_buf, "/confs/default.json");
    ASSERT_NE(pwd, nullptr);
    std::cout << "cni conf path: " << pwd_buf << std::endl;
    ret = cni_conf_from_file(pwd_buf, &config, &err);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(config, nullptr);
    free(err);
    err = nullptr;
    free_cni_network_conf(config);
    config = nullptr;
    memset(pwd_buf, 0, PATH_MAX);

    ret = cni_conf_from_file("/tmp/xxx/xxx.json", &config, &err);
    ASSERT_NE(ret, 0);
    ASSERT_EQ(config, nullptr);
    free(err);
    err = nullptr;
}


TEST(api_testcases, cni_conflist_from_file)
{
    int ret = 0;
    char pwd_buf[PATH_MAX] = {0X0};
    char *pwd = nullptr;
    char *err = NULL;
    struct cni_network_list_conf *list = nullptr;

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);
    pwd = strcat(pwd_buf, "/confs/test-invalid.conflist");
    ASSERT_NE(pwd, nullptr);
    std::cout << "cni conflist path: " << pwd_buf << std::endl;
    ret = cni_conflist_from_file(pwd_buf, &list, &err);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(list, nullptr);
    free(err);
    err = nullptr;
    free_cni_network_list_conf(list);
    list = nullptr;
    memset(pwd_buf, 0, PATH_MAX);

    pwd = getcwd(pwd_buf, PATH_MAX);
    ASSERT_NE(pwd, nullptr);
    pwd = strcat(pwd_buf, "/confs/test.conflist");
    ASSERT_NE(pwd, nullptr);
    std::cout << "cni conflist path: " << pwd_buf << std::endl;
    ret = cni_conflist_from_file(pwd_buf, &list, &err);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(list, nullptr);
    free(err);
    err = nullptr;
    free_cni_network_list_conf(list);
    list = nullptr;
    memset(pwd_buf, 0, PATH_MAX);

    ret = cni_conflist_from_file("/tmp/xxx/xxx.json", &list, &err);
    ASSERT_NE(ret, 0);
    ASSERT_EQ(list, nullptr);
    free(err);
    err = nullptr;
}

TEST(api_testcases, free_cni_port_mapping)
{
    int ret = 0;
    struct cni_port_mapping *cpm = (struct cni_port_mapping *)malloc(sizeof(struct cni_port_mapping));

    cpm->container_port = 80;
    cpm->host_port = 8080;
    cpm->protocol = strdup("tcp");
    cpm->host_ip = nullptr;

    free_cni_port_mapping(cpm);
}

TEST(api_testcases, free_runtime_conf)
{
    int ret = 0;
    struct runtime_conf *rc = (struct runtime_conf *)calloc(sizeof(struct runtime_conf), 1);

    rc->ifname = strdup("eth0");
    rc->p_mapping_len = 2;
    rc->p_mapping = (struct cni_port_mapping **)calloc(sizeof(struct cni_port_mapping *), 2);
    rc->p_mapping[0] = (struct cni_port_mapping *)calloc(sizeof(struct cni_port_mapping), 1);
    rc->p_mapping[1] = (struct cni_port_mapping *)calloc(sizeof(struct cni_port_mapping), 1);

    free_runtime_conf(rc);
}