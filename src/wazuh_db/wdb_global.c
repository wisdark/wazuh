/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

// List of agent information fields in global DB
// The ":" is used for parameter binding
static const char *global_db_agent_fields[] = {
    ":config_sum",
    ":ip",
    ":manager_host",
    ":merged_sum",
    ":name",
    ":node_name",
    ":os_arch",
    ":os_build",
    ":os_codename",
    ":os_major",
    ":os_minor",
    ":os_name",
    ":os_platform",
    ":os_uname",
    ":os_version",
    ":version",
    ":last_keepalive",
    ":connection_status",
    ":id",
    NULL
};

int wdb_global_insert_agent(wdb_t *wdb, int id, char* name, char* ip, char* register_ip, char* internal_key, char* group, int date_add) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_INSERT_AGENT) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_INSERT_AGENT];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 3, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 4, register_ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 5, internal_key, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 6, date_add) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 7, group, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_agent_name(wdb_t *wdb, int id, char* name) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_NAME) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_NAME];

    if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_agent_version(wdb_t *wdb,
                                    int id,
                                    const char *os_name,
                                    const char *os_version,
                                    const char *os_major,
                                    const char *os_minor,
                                    const char *os_codename,
                                    const char *os_platform,
                                    const char *os_build,
                                    const char *os_uname,
                                    const char *os_arch,
                                    const char *version,
                                    const char *config_sum,
                                    const char *merged_sum,
                                    const char *manager_host,
                                    const char *node_name,
                                    const char *agent_ip,
                                    const char *connection_status,
                                    const char *sync_status)
{
    sqlite3_stmt *stmt = NULL;
    int index = 1;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, agent_ip ? WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP : WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[agent_ip ? WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP : WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION];

    if (sqlite3_bind_text(stmt, index++, os_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_version, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_major, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_minor, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_codename, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_platform, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_build, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_uname, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_arch, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, version, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, config_sum, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, merged_sum, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, manager_host, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, node_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (agent_ip) {
        if (sqlite3_bind_text(stmt, index++, agent_ip, -1, NULL) != SQLITE_OK) {
            merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            return OS_INVALID;
        }
    }
    if (sqlite3_bind_text(stmt, index++, connection_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, index++, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_get_agent_labels(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_GET) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_GET];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_del_agent_labels(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_DEL) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_DEL];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_set_agent_label(wdb_t *wdb, int id, char* key, char* value) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_SET) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_SET];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, key, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 3, value, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_agent_keepalive(wdb_t *wdb, int id, const char *connection_status, const char* sync_status) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE];

    if (sqlite3_bind_text(stmt, 1, connection_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 3, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_agent_connection_status(wdb_t *wdb, int id, const char* connection_status, const char *sync_status) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS];

    if (sqlite3_bind_text(stmt, 1, connection_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 3, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_delete_agent(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_AGENT) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_AGENT];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_select_agent_name(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_AGENT_NAME) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_AGENT_NAME];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_select_agent_group(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_AGENT_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_AGENT_GROUP];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_find_agent(wdb_t *wdb, const char *name, const char *ip) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_FIND_AGENT) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_FIND_AGENT];

    if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 2, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 3, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_update_agent_group(wdb_t *wdb, int id, char *group) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_GROUP];

    if (sqlite3_bind_text(stmt, 1, group, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_find_group(wdb_t *wdb, char* group_name) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_FIND_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_FIND_GROUP];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_insert_agent_group(wdb_t *wdb, char* group_name) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_INSERT_AGENT_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_INSERT_AGENT_GROUP];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_insert_agent_belong(wdb_t *wdb, int id_group, int id_agent) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_INSERT_AGENT_BELONG) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_INSERT_AGENT_BELONG];

    if (sqlite3_bind_int(stmt, 1, id_group) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id_agent) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_delete_group_belong(wdb_t *wdb, char* group_name) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_GROUP_BELONG) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_GROUP_BELONG];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_delete_group(wdb_t *wdb, char* group_name) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_GROUP];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_select_groups(wdb_t *wdb) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_GROUPS) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_GROUPS];

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_select_agent_keepalive(wdb_t *wdb, char* name, char* ip) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_AGENT_KEEPALIVE) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_AGENT_KEEPALIVE];

    if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 2, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 3, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_delete_agent_belong(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_AGENT_BELONG) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_AGENT_BELONG];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_set_sync_status(wdb_t *wdb, int id, const char* sync_status) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SYNC_SET) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SYNC_SET];

    if (sqlite3_bind_text(stmt, 1, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

wdbc_result wdb_global_sync_agent_info_get(wdb_t *wdb, int* last_agent_id, char **output) {
    sqlite3_stmt* agent_stmt = NULL;
    unsigned response_size = 2;     //Starts with "[]" size
    wdbc_result status = WDBC_UNKNOWN;

    os_calloc(WDB_MAX_RESPONSE_SIZE, sizeof(char), *output);
    char *response_aux = *output;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot begin transaction");
        return WDBC_ERROR;
    }

    //Add array start
    *response_aux++ = '[';

    while (status == WDBC_UNKNOWN) {
        //Prepare SQL query
        if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SYNC_REQ_GET) < 0) {
            mdebug1("Cannot cache statement");
            snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot cache statement");
            status = WDBC_ERROR;
            break;
        }
        agent_stmt = wdb->stmt[WDB_STMT_GLOBAL_SYNC_REQ_GET];
        if (sqlite3_bind_int(agent_stmt, 1, *last_agent_id) != SQLITE_OK) {
            merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot bind sql statement");
            status = WDBC_ERROR;
            break;
        }

        //Get agent info
        cJSON* sql_agents_response = wdb_exec_stmt(agent_stmt);
        if (sql_agents_response && sql_agents_response->child) {
            cJSON* json_agent = sql_agents_response->child;
            cJSON* json_id = cJSON_GetObjectItem(json_agent,"id");
            if (cJSON_IsNumber(json_id)) {
                //Get ID
                int agent_id = json_id->valueint;

                //Get labels if any
                cJSON* json_labels = wdb_global_get_agent_labels(wdb, agent_id);
                if (json_labels) {
                    if (json_labels->child) {
                        cJSON_AddItemToObject(json_agent, "labels", json_labels);
                    }
                    else {
                        cJSON_Delete(json_labels);
                    }
                }

                //Print Agent info
                char *agent_str = cJSON_PrintUnformatted(json_agent);
                unsigned agent_len = strlen(agent_str);

                //Check if new agent fits in response
                if (response_size+agent_len+1 < WDB_MAX_RESPONSE_SIZE) {
                    //Add new agent
                    memcpy(response_aux, agent_str, agent_len);
                    response_aux+=agent_len;
                    //Add separator
                    *response_aux++ = ',';
                    //Save size and last ID
                    response_size += agent_len+1;
                    *last_agent_id = agent_id;
                    //Set sync status as synced
                    if (OS_SUCCESS != wdb_global_set_sync_status(wdb, agent_id, "synced")) {
                        merror("Cannot set sync_status for agent %d", agent_id);
                        snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s %d", "Cannot set sync_status for agent", agent_id);
                        status = WDBC_ERROR;
                    }
                }
                else {
                    //Pending agents but buffer is full
                    status = WDBC_DUE;
                }
                os_free(agent_str);
            }
        }
        else {
            //All agents have been obtained
            status = WDBC_OK;
        }
        cJSON_Delete(sql_agents_response);
    }

    if (status != WDBC_ERROR) {
        if (response_size > 2) {
            //Remove last ','
            response_aux--;
        }
        //Add array end
        *response_aux = ']';
    }
    return status;
}

int wdb_global_sync_agent_info_set(wdb_t *wdb,cJSON * json_agent){
    sqlite3_stmt *stmt = NULL;
    int n = 0;
    int index = 0;
    cJSON *json_field = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_INFO) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_INFO];

    for (n = 0 ; global_db_agent_fields[n] ; n++){
        // Every column name of Global DB is stored in global_db_agent_fields
        json_field = cJSON_GetObjectItem(json_agent, global_db_agent_fields[n]+1);
        index = sqlite3_bind_parameter_index(stmt, global_db_agent_fields[n]);
        if (cJSON_IsNumber(json_field) && index != 0){
            if (sqlite3_bind_int(stmt, index , json_field->valueint) != SQLITE_OK) {
                merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }

        } else if (cJSON_IsString(json_field) && json_field->valuestring != NULL && index != 0) {
            if (sqlite3_bind_text(stmt, index , json_field->valuestring, -1, NULL) != SQLITE_OK) {
                merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }
        }
    }

    index = sqlite3_bind_parameter_index(stmt, ":sync_status");
    if (sqlite3_bind_text(stmt, index, "synced", -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_get_agent_info(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENT_INFO) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENT_INFO];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_get_agents_to_disconnect(wdb_t *wdb, int last_agent_id, int keep_alive, const char *sync_status, wdbc_result* status) {
    sqlite3_stmt* stmt = NULL;

    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        *status = WDBC_ERROR;
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT) < 0) {
        mdebug1("Cannot cache statement");
        *status = WDBC_ERROR;
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT];

    if (sqlite3_bind_int(stmt, 1, last_agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    if (sqlite3_bind_int(stmt, 2, keep_alive) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status);
    if (SQLITE_DONE == sql_status) *status = WDBC_OK;
    else if (SQLITE_ROW == sql_status) *status = WDBC_DUE;
    else *status = WDBC_ERROR;

    //Set every obtained agent as 'disconnected'
    cJSON* agent = NULL;
    cJSON_ArrayForEach(agent, result) {
        cJSON* id = cJSON_GetObjectItem(agent,"id");
        if (cJSON_IsNumber(id)) {
            //Set connection status as disconnected
            if (OS_SUCCESS != wdb_global_update_agent_connection_status(wdb, id->valueint, "disconnected", sync_status)) {
                merror("Cannot set connection_status for agent %d", id->valueint);
                *status = WDBC_ERROR;
            }
        }
        else {
            merror("Invalid element returned by disconnect query");
            *status = WDBC_ERROR;
        }
    }

    return result;
}

cJSON* wdb_global_get_all_agents(wdb_t *wdb, int last_agent_id, wdbc_result* status) {
    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        *status = WDBC_ERROR;
        return NULL;
    }
    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS) < 0) {
        mdebug1("Cannot cache statement");
        *status = WDBC_ERROR;
        return NULL;
    }
    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS];
    if (sqlite3_bind_int(stmt, 1, last_agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status);
    if (SQLITE_DONE == sql_status) *status = WDBC_OK;
    else if (SQLITE_ROW == sql_status) *status = WDBC_DUE;
    else *status = WDBC_ERROR;

    return result;
}

int wdb_global_reset_agents_connection(wdb_t *wdb, const char *sync_status) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS];

    if (sqlite3_bind_text(stmt, 1, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_get_agents_by_connection_status (wdb_t *wdb, int last_agent_id, const char* connection_status, wdbc_result* status) {
    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        *status = WDBC_ERROR;
        return NULL;
    }
    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS) < 0) {
        mdebug1("Cannot cache statement");
        *status = WDBC_ERROR;
        return NULL;
    }
    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS];
    if (sqlite3_bind_int(stmt, 1, last_agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 2, connection_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status);
    if (SQLITE_DONE == sql_status) *status = WDBC_OK;
    else if (SQLITE_ROW == sql_status) *status = WDBC_DUE;
    else *status = WDBC_ERROR;

    return result;
}
