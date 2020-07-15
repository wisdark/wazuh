/*
 * SQL Schema SCA tests
 * Copyright (C) 2015-2020, Wazuh Inc.
 * March 25, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE IF NOT EXISTS ciscat_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    scan_time TEXT,
    benchmark TEXT,
    profile TEXT,
    pass INTEGER,
    fail INTEGER,
    error INTEGER,
    notchecked INTEGER,
    unknown INTEGER,
    score INTEGER
);

CREATE INDEX IF NOT EXISTS ciscat_id ON ciscat_results (scan_id);

INSERT INTO ciscat_results VALUES (1, 1406741147, '2018-09-06T07:50:15.632Z',
                                   'CIS Ubuntu Linux 16.04 LTS Benchmark',
                                   'xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server', 93, 60, 0, 67, 0, 61);
INSERT INTO ciscat_results VALUES (2, 1406741147, '2018-09-06T07:50:52.630Z',
                                   'CIS Ubuntu Linux 16.04 LTS Benchmark',
                                   'xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Workstation', 96, 53, 0, 71, 0, 64);
