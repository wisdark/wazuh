/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef MANAGE_AGENTS_WRAPPERS_H
#define MANAGE_AGENTS_WRAPPERS_H

void __wrap_OS_RemoveAgentGroup(const char *id);

#endif
