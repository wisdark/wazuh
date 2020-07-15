/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef DODIFF_H
#define DODIFF_H

#include "rules.h"
#include "eventinfo.h"

int doDiff(RuleInfo *rule, Eventinfo *lf);


#endif /* DODIFF_H */
