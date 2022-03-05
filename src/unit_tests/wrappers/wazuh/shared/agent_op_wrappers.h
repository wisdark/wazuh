/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef AGENT_OP_WRAPPERS_H
#define AGENT_OP_WRAPPERS_H

int __wrap_auth_connect();
char* __wrap_get_agent_id_from_name(__attribute__((unused)) char *agent_name);
int __wrap_control_check_connection();
int __wrap_get_agent_group(const char *id, char *group, __attribute__((unused)) size_t size);
int __wrap_set_agent_group(const char * id, const char * group);

#endif
