/*
 * JSON support library
 * Copyright (C) 2015-2020, Wazuh Inc.
 * May 11, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef JSON_OP_H
#define JSON_OP_H

#define JSON_MAX_FSIZE 536870912

#include <external/cJSON/cJSON.h>

cJSON * json_fread(const char * path, char retry);
int json_fwrite(const char * path, const cJSON * item);

// Clear C/C++ style comments from a JSON string
void json_strip(char * json);

// Check if a JSON object is tagged
#define json_tagged_obj(x) (x && x->string)

#endif
