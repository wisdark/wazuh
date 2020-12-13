/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "stat_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../common.h"


int __wrap_chmod(const char *path) {
    check_expected_ptr(path);
    return mock();
}

int __wrap_chown(const char *__file, int __owner, int __group) {
    check_expected(__file);
    check_expected(__owner);
    check_expected(__group);

    return mock();
}

int __wrap_lstat(const char *filename, struct stat *buf) {
    check_expected(filename);
    buf->st_mode = mock();
    return mock();
}

#ifdef WIN32
int __wrap_mkdir(const char *__path) {
    check_expected(__path);
    return mock();
}
#elif defined(__MACH__)
int __wrap_mkdir(const char *__path, mode_t __mode) {
    check_expected(__path);
    check_expected(__mode);
    return mock();
}
#else
int __wrap_mkdir(const char *__path, __mode_t __mode) {
    check_expected(__path);
    check_expected(__mode);
    return mock();
}
#endif

extern int __real_stat(const char * __file, struct stat * __buf);
int __wrap_stat(const char * __file, struct stat * __buf) {
    if (test_mode) {
        check_expected(__file);
        __buf->st_mode = mock();
        __buf->st_size = __buf->st_mode;
        return mock_type(int);
    }
    return __real_stat(__file, __buf);
}
