/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "common.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

time_t time_mock_value;

int FOREVER() {
    return 1;
}


int __wrap_FOREVER() {
    return mock();
}

time_t wrap_time (__attribute__((unused)) time_t *t) {
    return time_mock_value;
}
