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
 * Author: wujing
 * Create: 2019-4-08
 * Description: provide container log functions
 ******************************************************************************/
#ifndef __CLIBCNI_LOG_H
#define __CLIBCNI_LOG_H

#include <stdbool.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif

#define CLIBCNI_LOG_BUFFER_SIZE 4096

/* We're logging in seconds and nanoseconds. Assuming that the underlying
 * datatype is currently at maximum a 64bit integer, we have a date string that
 * is of maximum length (2^64 - 1) * 2 = (21 + 21) = 42.
 * */
#define CLIBCNI_LOG_TIME_SIZE 42

enum clibcni_log_drivers {
    LOG_DRIVER_STDOUT,
    LOG_DRIVER_FIFO,
    LOG_DRIVER_SYSLOG,
    LOG_DRIVER_NOSET,
};

enum clibcni_log_level {
    CLIBCNI_LOG_FATAL = 0,
    CLIBCNI_LOG_ALERT,
    CLIBCNI_LOG_CRIT,
    CLIBCNI_LOG_ERROR,
    CLIBCNI_LOG_WARN,
    CLIBCNI_LOG_NOTICE,
    CLIBCNI_LOG_INFO,
    CLIBCNI_LOG_DEBUG,
    CLIBCNI_LOG_TRACE,
    CLIBCNI_LOG_MAX
};

struct clibcni_log_config {
    const char *name;
    const char *file;
    const char *priority;
    const char *prefix;
    const char *driver;
    bool quiet;
};

#define CLIBCNI_LOG_LOCINFO_INIT                               \
    {                                                         \
        .file = __FILE__, .func = __func__, .line = __LINE__, \
    }

/* brief logging event object */
struct clibcni_log_object_metadata {
    /* location information of the logging item */
    const char *file;
    const char *func;
    int line;

    int level;
};

int clibcni_log_enable(const struct clibcni_log_config *log);

void clibcni_set_log_prefix(const char *prefix);

void clibcni_free_log_prefix(void);

int clibcni_log_append(const struct clibcni_log_object_metadata *metadata, const char *format, ...);

#define COMMON_LOG(loglevel, format, ...)                                      \
    do {                                                                    \
        struct clibcni_log_object_metadata meta = CLIBCNI_LOG_LOCINFO_INIT;   \
        meta.level = loglevel;                                          \
        (void)clibcni_log_append(&meta, format, ##__VA_ARGS__);              \
    } while (0)

#define DEBUG(format, ...)                                            \
    COMMON_LOG(CLIBCNI_LOG_DEBUG, format, ##__VA_ARGS__)

#define INFO(format, ...)                                             \
    COMMON_LOG(CLIBCNI_LOG_INFO, format, ##__VA_ARGS__)

#define NOTICE(format, ...)                                           \
    COMMON_LOG(CLIBCNI_LOG_NOTICE, format, ##__VA_ARGS__)

#define WARN(format, ...)                                             \
    COMMON_LOG(CLIBCNI_LOG_WARN, format, ##__VA_ARGS__)

#define ERROR(format, ...)                                            \
    COMMON_LOG(CLIBCNI_LOG_ERROR, format, ##__VA_ARGS__)

#define CRIT(format, ...)                                             \
    COMMON_LOG(CLIBCNI_LOG_CRIT, format, ##__VA_ARGS__)

#define ALERT(format, ...)                                            \
    COMMON_LOG(CLIBCNI_LOG_ALERT, format, ##__VA_ARGS__)

#define FATAL(format, ...)                                            \
    COMMON_LOG(CLIBCNI_LOG_FATAL, format, ##__VA_ARGS__)

#define SYSERROR(format, ...)                                  \
    do {                                                       \
        ERROR("%s - " format, strerror(errno), ##__VA_ARGS__); \
    } while (0)

#define COMMAND_ERROR(fmt, args...)              \
    do {                                         \
        (void)fprintf(stderr, fmt "\n", ##args); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* __LCR_LOG_H */
