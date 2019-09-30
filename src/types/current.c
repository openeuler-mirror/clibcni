/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * clibcni licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide result functions
 ********************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "current.h"
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "log.h"

static struct result *get_result(const result_curr *curr_result, char **err);

static result_curr *new_curr_result_helper(const char *json_data, char **err)
{
    result_curr *result = NULL;
    parser_error errmsg = NULL;

    if (json_data == NULL) {
        ERROR("Json data is NULL");
        return NULL;
    }
    result = result_curr_parse_data(json_data, NULL, &errmsg);
    if (result == NULL) {
        if (asprintf(err, "parse json failed: %s", errmsg) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        ERROR("Parse failed: %s", errmsg);
        goto free_out;
    }
    return result;

free_out:
    free(errmsg);
    return NULL;
}

static void do_append_result_errmsg(const struct result *ret, const char *save_err, char **err)
{
    char *tmp_err = NULL;
    int nret = 0;

    if (ret != NULL) {
        return;
    }

    tmp_err = *err;
    *err = NULL;
    nret = asprintf(err, "parse err: %s, convert err: %s", save_err ? save_err : "", tmp_err ? tmp_err : "");
    if (nret < 0) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
    }
    free(tmp_err);
}

struct result *new_curr_result(const char *json_data, char **err)
{
    struct result *ret = NULL;
    result_curr *tmp_result = NULL;
    char *save_err = NULL;

    if (err == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }
    tmp_result = new_curr_result_helper(json_data, err);
    if (tmp_result == NULL) {
        return NULL;
    }
    if (*err != NULL) {
        save_err = *err;
        *err = NULL;
    }
    ret = get_result(tmp_result, err);
    do_append_result_errmsg(ret, save_err, err);

    free_result_curr(tmp_result);
    free(save_err);
    return ret;
}

static struct interface *convert_curr_interface(const network_interface *curr_interface)
    {
        struct interface *result = NULL;

        if (curr_interface == NULL) {
            ERROR("Invalid argument");
            return NULL;
        }

        result = util_common_calloc_s(sizeof(struct interface));
        if (result == NULL) {
            ERROR("Out of memory");
            return NULL;
        }

        result->name = util_strdup_s(curr_interface->name);
        result->mac = util_strdup_s(curr_interface->mac);
        result->sandbox = util_strdup_s(curr_interface->sandbox);
        return result;
    }

static int do_parse_ipnet(const char *cidr_str, const char *ip_str, uint8_t **ip, size_t *ip_len,
                          struct ipnet **ipnet_val, char **err)
{
    int ret = 0;

    ret = parse_cidr(cidr_str, ipnet_val, err);
    if (ret != 0) {
        ERROR("Parse cidr failed: %s", *err != NULL ? *err : "");
        return -1;
    }
    ret = parse_ip_from_str(ip_str, ip, ip_len, err);
    if (ret != 0) {
        ERROR("Parse ip failed: %s", *err != NULL ? *err : "");
        free_ipnet_type(*ipnet_val);
        *ipnet_val = NULL;
        return -1;
    }
    return 0;
}

static struct ipconfig *convert_curr_ipconfig(const network_ipconfig *curr_ipconfig, char **err)
{
    struct ipconfig *result = NULL;
    struct ipnet *ipnet_val = NULL;
    int ret = 0;
    uint8_t *gateway = NULL;
    size_t gateway_len = 0;

    if (curr_ipconfig == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }

    result = util_common_calloc_s(sizeof(struct ipconfig));
    if (result == NULL) {
        ERROR("Out of memory");
        *err = util_strdup_s("Out of memory");
        return NULL;
    }
    /* parse address to ipnet */
    ret = do_parse_ipnet(curr_ipconfig->address, curr_ipconfig->gateway, &gateway, &gateway_len, &ipnet_val, err);
    if (ret != 0) {
        goto err_out;
    }
    result->address = ipnet_val;
    result->gateway = gateway;
    result->gateway_len = gateway_len;
    result->version = util_strdup_s(curr_ipconfig->version);

    if (curr_ipconfig->interface != NULL) {
        result->interface = util_common_calloc_s(sizeof(int32_t));
        if (result->interface == NULL) {
            ERROR("Out of memory");
            *err = util_strdup_s("Out of memory");
            goto err_out;
        }
        *(result->interface) = *(curr_ipconfig->interface);
    }

    return result;

err_out:
    free_ipconfig_type(result);
    return NULL;
}

static struct route *convert_curr_route(const network_route *curr_route, char **err)
{
    struct route *result = NULL;
    struct ipnet *dst = NULL;
    int ret = 0;
    uint8_t *gw = NULL;
    size_t gw_len = 0;

    if (curr_route == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }
    ret = do_parse_ipnet(curr_route->dst, curr_route->gw, &gw, &gw_len, &dst, err);
    if (ret != 0) {
        return NULL;
    }

    result = util_common_calloc_s(sizeof(struct route));
    if (result == NULL) {
        ERROR("Out of memory");
        free(gw);
        free_ipnet_type(dst);
        *err = util_strdup_s("Out of memory");
        return NULL;
    }

    result->dst = dst;
    result->gw = gw;
    result->gw_len = gw_len;

    return result;
}

static struct dns *convert_curr_dns(network_dns *curr_dns, char **err)
{
    struct dns *result = NULL;

    if (curr_dns == NULL) {
        *err = util_strdup_s("Empty dns argument");
        ERROR("Empty dns argument");
        return NULL;
    }

    result = util_common_calloc_s(sizeof(struct dns));
    if (result == NULL) {
        ERROR("Out of memory");
        *err = util_strdup_s("Out of memory");
        return NULL;
    }

    result->name_servers = curr_dns->nameservers;
    result->name_servers_len = curr_dns->nameservers_len;
    result->domain = curr_dns->domain;
    result->options = curr_dns->options;
    result->options_len = curr_dns->options_len;
    result->search = curr_dns->search;
    result->search_len = curr_dns->search_len;

    if (memset_s(curr_dns, sizeof(network_dns), 0, sizeof(network_dns)) != EOK) {
        *err = util_strdup_s("Memset failed");
        ERROR("Memset failed");
    }

    return result;
}

static int copy_result_interface(const result_curr *curr_result, struct result *value, char **err)
{
    value->interfaces_len = curr_result->interfaces_len;
    if (value->interfaces_len > 0) {
        if (value->interfaces_len > (SIZE_MAX / sizeof(struct interface *))) {
            *err = util_strdup_s("Too many interface");
            value->interfaces_len = 0;
            ERROR("Too many interface");
            return -1;
        }
        value->interfaces = util_common_calloc_s(sizeof(struct interface *) * value->interfaces_len);
        if (value->interfaces == NULL) {
            *err = util_strdup_s("Out of memory");
            value->interfaces_len = 0;
            ERROR("Out of memory");
            return -1;
        }
        size_t i;
        for (i = 0; i < curr_result->interfaces_len; i++) {
            value->interfaces[i] = convert_curr_interface(curr_result->interfaces[i]);
            if (value->interfaces[i] == NULL) {
                *err = util_strdup_s("Convert interfaces failed");
                value->interfaces_len = i;
                ERROR("Convert interfaces failed");
                return -1;
            }
        }
    }
    return 0;
}

static int copy_result_ips(const result_curr *curr_result, struct result *value, char **err)
{
    size_t i = 0;
    value->ips_len = curr_result->ips_len;

    if (value->ips_len == 0) {
        return 0;
    }

    if (value->ips_len > (SIZE_MAX / sizeof(struct ipconfig *))) {
        *err = util_strdup_s("Too many ips");
        ERROR("Too many ips");
        value->ips_len = 0;
        return -1;
    }

    value->ips = util_common_calloc_s(sizeof(struct ipconfig *) * value->ips_len);
    if (value->ips == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        value->ips_len = 0;
        return -1;
    }
    for (i = 0; i < value->ips_len; i++) {
        value->ips[i] = convert_curr_ipconfig(curr_result->ips[i], err);
        if (value->ips[i] == NULL) {
            ERROR("Convert ips failed: %s", *err != NULL ? *err : "");
            value->ips_len = i;
            return -1;
        }
    }
    return 0;
}

static int copy_result_routes(const result_curr *curr_result, struct result *value, char **err)
{
    size_t i = 0;

    value->routes_len = curr_result->routes_len;
    if (value->routes_len == 0) {
        return 0;
    }

    if (value->routes_len > (SIZE_MAX / sizeof(struct route *))) {
        *err = util_strdup_s("Too many routes");
        ERROR("Too many routes");
        value->routes_len = 0;
        return -1;
    }

    value->routes = util_common_calloc_s(sizeof(struct route *) * value->routes_len);
    if (value->routes == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        value->routes_len = 0;
        return -1;
    }
    for (i = 0; i < value->routes_len; i++) {
        value->routes[i] = convert_curr_route(curr_result->routes[i], err);
        if (value->routes[i] == NULL) {
            ERROR("Convert routes failed: %s", *err != NULL ? *err : "");
            value->routes_len = i;
            return -1;
        }
    }
    return 0;
}

static struct result *get_result(const result_curr *curr_result, char **err)
{
    struct result *value = NULL;
    bool invalid_arg = (curr_result == NULL || err == NULL);

    if (invalid_arg) {
        return NULL;
    }
    value = util_common_calloc_s(sizeof(struct result));
    if (value == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        return NULL;
    }

    /* copy cni version */
    value->cniversion = util_strdup_s(curr_result->cni_version);

    /* copy interfaces */
    if (copy_result_interface(curr_result, value, err) != 0) {
        goto free_out;
    }

    /* copy ips */
    if (copy_result_ips(curr_result, value, err) != 0) {
        goto free_out;
    }

    /* copy routes */
    if (copy_result_routes(curr_result, value, err) != 0) {
        goto free_out;
    }

    /* copy dns */
    value->my_dns = convert_curr_dns(curr_result->dns, err);
    if (value->my_dns == NULL) {
        goto free_out;
    }

    return value;
free_out:
    free_result(value);
    return NULL;
}

static network_interface *interface_to_json_interface(const struct interface *src)
{
    network_interface *result = NULL;

    if (src == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    result = util_common_calloc_s(sizeof(network_interface));
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    result->name = util_strdup_s(src->name);
    result->mac = util_strdup_s(src->mac);
    result->sandbox = util_strdup_s(src->sandbox);

    return result;
}

static int parse_ip_and_gateway(const struct ipconfig *src, network_ipconfig *result, char **err)
{
    if (src->address != NULL) {
        result->address = ipnet_to_string(src->address, err);
        if (result->address == NULL) {
            ERROR("Covert ipnet failed: %s", *err != NULL ? *err : "");
            return -1;
        }
    }

    if (src->gateway && src->gateway_len > 0) {
        result->gateway = ip_to_string(src->gateway, src->gateway_len);
        if (result->gateway == NULL) {
            if (asprintf(err, "ip: %s to string failed", src->gateway) < 0) {
                *err = util_strdup_s("ip to string failed");
            }
            ERROR("IP: %s to string failed", src->gateway);
            return -1;
        }
    }
    return 0;
}

static network_ipconfig *ipconfig_to_json_ipconfig(const struct ipconfig *src, char **err)
{
    network_ipconfig *result = NULL;
    int ret = -1;

    if (src == NULL) {
        ERROR("Invalid arguments");
        return result;
    }

    result = util_common_calloc_s(sizeof(network_ipconfig));
    if (result == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        goto out;
    }

    /* parse address and ip */
    if (parse_ip_and_gateway(src, result, err) != 0) {
        goto out;
    }

    if (src->version != NULL) {
        result->version = util_strdup_s(src->version);
    }

    if (src->interface != NULL) {
        result->interface = util_common_calloc_s(sizeof(int32_t));
        if (result->interface == NULL) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            goto out;
        }
        *(result->interface) = *(src->interface);
    }

    ret = 0;
out:
    if (ret != 0) {
        free_network_ipconfig(result);
        result = NULL;
    }
    return result;
}

static network_route *route_to_json_route(const struct route *src, char **err)
{
    network_route *result = NULL;
    int ret = -1;

    if (src == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    result = (network_route *)util_common_calloc_s(sizeof(network_route));
    if (result == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        goto out;
    }

    if (src->dst != NULL) {
        result->dst = ipnet_to_string(src->dst, err);
        if (result->dst == NULL) {
            goto out;
        }
    }

    if (src->gw != NULL && src->gw_len > 0) {
        result->gw = ip_to_string(src->gw, src->gw_len);
        if (result->gw == NULL) {
            *err = util_strdup_s("ip to string failed");
            ERROR("ip to string failed");
            goto out;
        }
    }

    ret = 0;
out:
    if (ret != 0) {
        free_network_route(result);
        result = NULL;
    }
    return result;
}

static int dns_to_json_copy_servers(const struct dns *src, network_dns *result, char **err)
{
    bool need_copy = (src->name_servers != NULL && src->name_servers_len > 0);

    if (need_copy) {
        if (src->name_servers_len > (SIZE_MAX / sizeof(char *))) {
            *err = util_strdup_s("Too many servers");
            ERROR("Too many servers");
            return -1;
        }

        result->nameservers = (char **)util_common_calloc_s(sizeof(char *) * src->name_servers_len);
        if (result->nameservers == NULL) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            return -1;
        }
        result->nameservers_len = src->name_servers_len;
        if (memcpy_s(result->nameservers, result->nameservers_len, src->name_servers, src->name_servers_len) != EOK) {
            *err = util_strdup_s("Memcpy failed");
            ERROR("Memcpy failed");
            return -1;
        }
    }
    return 0;
}

static int dns_to_json_copy_options(const struct dns *src, network_dns *result, char **err)
{
    bool need_copy = (src->options != NULL && src->options_len > 0);

    if (need_copy) {
        if (src->options_len > (SIZE_MAX / sizeof(char *))) {
            *err = util_strdup_s("Too many options");
            ERROR("Too many options");
            return -1;
        }

        result->options = (char **)util_common_calloc_s(sizeof(char *) * src->options_len);
        if (result->options == NULL) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            return -1;
        }
        result->options_len = src->options_len;
        if (memcpy_s(result->options, result->options_len, src->options, src->options_len) != EOK) {
            *err = util_strdup_s("Memcpy failed");
            ERROR("Memcpy failed");
            return -1;
        }
    }
    return 0;
}

static int dns_to_json_copy_searchs(const struct dns *src, network_dns *result, char **err)
{
    bool need_copy = (src->search != NULL && src->search_len > 0);

    if (need_copy) {
        if (src->search_len > (SIZE_MAX / sizeof(char *))) {
            *err = util_strdup_s("Too many searchs");
            ERROR("Too many searchs");
            return -1;
        }

        result->search = (char **)util_common_calloc_s(sizeof(char *) * src->search_len);
        if (result->search == NULL) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            return -1;
        }
        result->search_len = src->search_len;
        if (memcpy_s(result->search, result->search_len, src->search, src->search_len) != EOK) {
            *err = util_strdup_s("Memcpy failed");
            ERROR("Memcpy failed");
            return -1;
        }
    }
    return 0;
}

static int do_copy_dns_configs_to_json(const struct dns *src, network_dns *result, char **err)
{
    if (dns_to_json_copy_servers(src, result, err) != 0) {
        return -1;
    }

    if (dns_to_json_copy_options(src, result, err) != 0) {
        return -1;
    }

    if (dns_to_json_copy_searchs(src, result, err) != 0) {
        return -1;
    }
    return 0;
}

static network_dns *dns_to_json_dns(const struct dns *src, char **err)
{
    network_dns *result = NULL;
    int ret = -1;

    if (src == NULL) {
        return NULL;
    }

    result = (network_dns *)util_common_calloc_s(sizeof(network_dns));
    if (result == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        goto out;
    }

    if (src->domain != NULL) {
        result->domain = util_strdup_s(src->domain);
    }

    ret = do_copy_dns_configs_to_json(src, result, err);
out:
    if (ret != 0) {
        free_network_dns(result);
        result = NULL;
    }
    return result;
}

static bool copy_interfaces_from_result_to_json(const struct result *src, result_curr *res, char **err)
{
    size_t i = 0;
    bool empty_src = (src->interfaces == NULL || src->interfaces_len == 0);

    if (empty_src) {
        return true;
    }

    res->interfaces_len = 0;

    if (src->interfaces_len > (SIZE_MAX / sizeof(network_interface *))) {
        *err = util_strdup_s("Too many interfaces");
        ERROR("Too many interfaces");
        return false;
    }

    res->interfaces = (network_interface **)util_common_calloc_s(sizeof(network_interface *) * src->interfaces_len);
    if (res->interfaces == NULL) {
        *err = util_strdup_s("Out of memory");
        ERROR("Out of memory");
        return false;
    }
    for (i = 0; i < src->interfaces_len; i++) {
        if (src->interfaces[i] == NULL) {
            continue;
        }
        res->interfaces[i] = interface_to_json_interface(src->interfaces[i]);
        if (res->interfaces[i] == NULL) {
            *err = util_strdup_s("interface to json struct failed");
            ERROR("interface to json struct failed");
            return false;
        }
        res->interfaces_len++;
    }
    return true;
}

static bool copy_ips_from_result_to_json(const struct result *src, result_curr *res, char **err)
{
    bool need_copy = (src->ips && src->ips_len > 0);

    res->ips_len = 0;
    if (need_copy) {
        if (src->ips_len > (SIZE_MAX / sizeof(network_ipconfig *))) {
            *err = util_strdup_s("Too many ips");
            ERROR("Too many ips");
            return false;
        }

        res->ips = (network_ipconfig **)util_common_calloc_s(sizeof(network_ipconfig *) * src->ips_len);
        if (res->ips == NULL) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            return false;
        }
        size_t i = 0;
        for (i = 0; i < src->ips_len; i++) {
            res->ips[i] = ipconfig_to_json_ipconfig(src->ips[i], err);
            if (res->ips[i] == NULL) {
                ERROR("parse ip failed: %s", *err != NULL ? *err : "");
                return false;
            }
            res->ips_len++;
        }
    }
    return true;
}

static bool copy_routes_from_result_to_json(const struct result *src, result_curr *res, char **err)
{
    bool need_copy = (src->routes && src->routes_len > 0);

    res->routes_len = 0;
    if (need_copy) {
        if (src->routes_len > (SIZE_MAX / sizeof(network_route *))) {
            *err = util_strdup_s("Too many routes");
            ERROR("Too many routes");
            return false;
        }
        res->routes = (network_route **)util_common_calloc_s(sizeof(network_route *) * src->routes_len);
        if (res->routes == NULL) {
            *err = util_strdup_s("Out of memory");
            ERROR("Out of memory");
            return false;
        }
        size_t i = 0;
        for (i = 0; i < src->routes_len; i++) {
            res->routes[i] = route_to_json_route(src->routes[i], err);
            if (res->routes[i] == NULL) {
                ERROR("Parse route failed: %s", *err != NULL ? *err : "");
                return false;
            }
            res->routes_len++;
        }
    }
    return true;
}

static int do_result_copy_configs_to_json(const struct result *src, result_curr *res, char **err)
{
    /* copy interfaces */
    if (!copy_interfaces_from_result_to_json(src, res, err)) {
        return -1;
    }

    /* copy ips */
    if (!copy_ips_from_result_to_json(src, res, err)) {
        return -1;
    }

    /* copy routes */
    if (!copy_routes_from_result_to_json(src, res, err)) {
        return -1;
    }

    /* copy dns */
    if (src->my_dns != NULL) {
        res->dns = dns_to_json_dns(src->my_dns, err);
        if (res->dns == NULL) {
            return -1;
        }
    }

    return 0;
}

result_curr *result_curr_to_json_result(const struct result *src, char **err)
{
    result_curr *res = NULL;
    int ret = -1;
    bool invalid_arg = (src == NULL || err == NULL);

    if (invalid_arg) {
        ERROR("Invalid arguments");
        return res;
    }

    res = (result_curr *)util_common_calloc_s(sizeof(result_curr));
    if (res == NULL) {
        ERROR("Out of memory");
        *err = util_strdup_s("Out of memory");
        goto out;
    }

    /* copy cni version */
    if (src->cniversion != NULL) {
        res->cni_version = util_strdup_s(src->cniversion);
    }

    ret = do_result_copy_configs_to_json(src, res, err);
out:
    if (ret != 0) {
        free_result_curr(res);
        res = NULL;
    }
    return res;
}

