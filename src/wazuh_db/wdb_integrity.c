/**
 * @file wdb_integrity.c
 * @brief DB integrity synchronization library definition.
 * @date 2019-08-14
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "os_crypto/sha1/sha1_op.h"
#include <openssl/evp.h>

static const char * COMPONENT_NAMES[] = {
    [WDB_FIM] = "fim",
    [WDB_FIM_FILE] = "fim_file",
    [WDB_FIM_REGISTRY] = "fim_registry",
    [WDB_SYSCOLLECTOR_PROCESSES] = "syscollector-processes",
    [WDB_SYSCOLLECTOR_PACKAGES] = "syscollector-packages",
    [WDB_SYSCOLLECTOR_HOTFIXES] = "syscollector-hotfixes",
    [WDB_SYSCOLLECTOR_PORTS] = "syscollector-ports",
    [WDB_SYSCOLLECTOR_NETPROTO] = "syscollector-netproto",
    [WDB_SYSCOLLECTOR_NETADDRESS] = "syscollector-netaddress",
    [WDB_SYSCOLLECTOR_NETINFO] = "syscollector-netinfo",
    [WDB_SYSCOLLECTOR_HWINFO] = "syscollector-hwinfo",
    [WDB_SYSCOLLECTOR_OSINFO] = "syscollector-osinfo"
};

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when unit testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

/**
 * @brief Run checksum of a data range
 *
 * @param[in] wdb Database node.
 * @param component[in] Name of the component.
 * @param begin[in] First element.
 * @param end[in] Last element.
 * @param[out] hexdigest
 * @retval 1 On success.
 * @retval 0 If no files were found in that range.
 * @retval -1 On error.
 */
int wdbi_checksum_range(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, os_sha1 hexdigest) {

    assert(wdb != NULL);
    assert(hexdigest != NULL);

    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_SELECT_CHECKSUM_RANGE,
                            [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_SELECT_CHECKSUM_RANGE,
                            [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM_RANGE,
                            [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM_RANGE    };

    assert(component < sizeof(INDEXES) / sizeof(int));

    if (wdb_stmt_cache(wdb, INDEXES[component]) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[INDEXES[component]];
    sqlite3_bind_text(stmt, 1, begin, -1, NULL);
    sqlite3_bind_text(stmt, 2, end, -1, NULL);

    int step = sqlite3_step(stmt);

    if (step != SQLITE_ROW) {
        return 0;
    }

    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, EVP_sha1());

    for (; step == SQLITE_ROW; step = sqlite3_step(stmt)) {
        const unsigned char * checksum = sqlite3_column_text(stmt, 0);

        if (checksum == 0) {
            mdebug1("DB(%s) has a NULL %s checksum.", wdb->id, COMPONENT_NAMES[component]);
            continue;
        }

        EVP_DigestUpdate(ctx, checksum, strlen((const char *)checksum));
    }

    // Get the hex SHA-1 digest

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;

    EVP_DigestFinal_ex(ctx, digest, &digest_size);
    EVP_MD_CTX_destroy(ctx);
    OS_SHA1_Hexdigest(digest, hexdigest);

    return 1;
}

/**
 * @brief Delete old elements in a table
 *
 * This function shall delete every item in the corresponding table,
 * between end and tail (none of them included).
 *
 * Should tail be NULL, this function will delete every item from the first
 * element to 'begin' and from 'end' to the last element.
 *
 * @param wdb Database node.
 * @param component Name of the component.
 * @param begin First valid element in the list.
 * @param end Last valid element. This is the previous element to the first item to delete.
 * @param tail Subsequent element to the last item to delete.
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdbi_delete(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, const char * tail) {

    assert(wdb != NULL);

    const int INDEXES_AROUND[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_AROUND,
                                   [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_DELETE_AROUND,
                                   [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_AROUND,
                                   [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_AROUND };
    const int INDEXES_RANGE[] = { [WDB_FIM] = WDB_STMT_FIM_DELETE_RANGE,
                                  [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_DELETE_RANGE,
                                  [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_RANGE,
                                  [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_RANGE };

    assert(component < sizeof(INDEXES_AROUND) / sizeof(int));
    assert(component < sizeof(INDEXES_RANGE) / sizeof(int));

    int index = tail ? INDEXES_RANGE[component] : INDEXES_AROUND[component];

    if (wdb_stmt_cache(wdb, index) == -1) {
        return -1;
    }

    sqlite3_stmt * stmt = wdb->stmt[index];

    if (tail) {
        sqlite3_bind_text(stmt, 1, end, -1, NULL);
        sqlite3_bind_text(stmt, 2, tail, -1, NULL);
    } else {
        sqlite3_bind_text(stmt, 1, begin, -1, NULL);
        sqlite3_bind_text(stmt, 2, end, -1, NULL);
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

void wdbi_update_attempt(wdb_t * wdb, wdb_component_t component, long timestamp, os_sha1 manager_checksum) {

    assert(wdb != NULL);

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_UPDATE_ATTEMPT) == -1) {
        return;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_UPDATE_ATTEMPT];

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_text(stmt, 2, manager_checksum, -1, NULL);
    sqlite3_bind_text(stmt, 3, COMPONENT_NAMES[component], -1, NULL);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
}

void wdbi_update_completion(wdb_t * wdb, wdb_component_t component, long timestamp, os_sha1 manager_checksum) {

    assert(wdb != NULL);

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_UPDATE_COMPLETION) == -1) {
        return;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_UPDATE_COMPLETION];

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_int64(stmt, 2, timestamp);
    sqlite3_bind_text(stmt, 3, manager_checksum, -1, NULL);
    sqlite3_bind_text(stmt, 4, COMPONENT_NAMES[component], -1, NULL);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
    }
}

// Query the checksum of a data range
integrity_sync_status_t wdbi_query_checksum(wdb_t * wdb, wdb_component_t component, dbsync_msg action, const char * payload) {
    integrity_sync_status_t status = INTEGRITY_SYNC_ERR;

    // Parse payload
    cJSON * data = cJSON_Parse(payload);
    if (data == NULL) {
        mdebug1("DB(%s): cannot parse checksum range payload: '%s'", wdb->id, payload);
        return -1;
    }
    cJSON * item = cJSON_GetObjectItem(data, "begin");
    char * begin = cJSON_GetStringValue(item);
    if (begin == NULL) {
        mdebug1("No such string 'begin' in JSON payload.");
        goto end;
    }
    item = cJSON_GetObjectItem(data, "end");
    char * end = cJSON_GetStringValue(item);
    if (end == NULL) {
        mdebug1("No such string 'end' in JSON payload.");
        goto end;
    }
    item = cJSON_GetObjectItem(data, "checksum");
    char * checksum = cJSON_GetStringValue(item);
    if (checksum == NULL) {
        mdebug1("No such string 'checksum' in JSON payload.");
        goto end;
    }
    item = cJSON_GetObjectItem(data, "id");
    if (!cJSON_IsNumber(item)) {
        mdebug1("No such string 'id' in JSON payload.");
        goto end;
    }
    long timestamp = item->valuedouble;

    os_sha1 manager_checksum = {0};
    // Get the previously computed manager checksum
    if (INTEGRITY_CHECK_GLOBAL == action) {
        if (OS_SUCCESS == wdbi_get_last_manager_checksum(wdb, component, manager_checksum) && 0 == strcmp(manager_checksum, checksum)) {
            mdebug2("Agent '%s' %s range checksum avoided.", wdb->id, COMPONENT_NAMES[component]);
            status = INTEGRITY_SYNC_CKS_OK;
        }
    }

    // Get the actual manager checksum
    if (status != INTEGRITY_SYNC_CKS_OK) {
        struct timespec ts_start, ts_end;
        gettime(&ts_start);
        switch (wdbi_checksum_range(wdb, component, begin, end, manager_checksum)) {
        case -1:
            goto end;

        case 0:
            status = INTEGRITY_SYNC_NO_DATA;
            break;

        case 1:
            gettime(&ts_end);
            mdebug2("Agent '%s' %s range checksum: Time: %.3f ms.", wdb->id, COMPONENT_NAMES[component], time_diff(&ts_start, &ts_end) * 1e3);
            status = strcmp(manager_checksum, checksum) ? INTEGRITY_SYNC_CKS_FAIL : INTEGRITY_SYNC_CKS_OK;
        }
    }

    // Update sync status
    if (INTEGRITY_CHECK_GLOBAL == action) {
        wdbi_delete(wdb, component, begin, end, NULL);
        switch (status) {
        case INTEGRITY_SYNC_NO_DATA:
        case INTEGRITY_SYNC_CKS_FAIL:
            wdbi_update_attempt(wdb, component, timestamp, "");
            break;

        case INTEGRITY_SYNC_CKS_OK:
            wdbi_update_completion(wdb, component, timestamp, manager_checksum);

        default:
            break;
        }

    }
    else if (INTEGRITY_CHECK_LEFT == action) {
        item = cJSON_GetObjectItem(data, "tail");
        wdbi_delete(wdb, component, begin, end, cJSON_GetStringValue(item));
    }

end:
    cJSON_Delete(data);
    return status;
}

// Query a complete table clear
int wdbi_query_clear(wdb_t * wdb, wdb_component_t component, const char * payload) {
    const int INDEXES[] = { [WDB_FIM] = WDB_STMT_FIM_CLEAR,
                            [WDB_FIM_FILE] = WDB_STMT_FIM_FILE_CLEAR,
                            [WDB_FIM_REGISTRY] = WDB_STMT_FIM_REGISTRY_CLEAR,
                            [WDB_SYSCOLLECTOR_PROCESSES] = WDB_STMT_SYSCOLLECTOR_PROCESSES_CLEAR,
                            [WDB_SYSCOLLECTOR_PACKAGES] = WDB_STMT_SYSCOLLECTOR_PACKAGES_CLEAR,
                            [WDB_SYSCOLLECTOR_HOTFIXES] = WDB_STMT_SYSCOLLECTOR_HOTFIXES_CLEAR,
                            [WDB_SYSCOLLECTOR_PORTS] = WDB_STMT_SYSCOLLECTOR_PORTS_CLEAR,
                            [WDB_SYSCOLLECTOR_NETPROTO] = WDB_STMT_SYSCOLLECTOR_NETPROTO_CLEAR,
                            [WDB_SYSCOLLECTOR_NETADDRESS] = WDB_STMT_SYSCOLLECTOR_NETADDRESS_CLEAR,
                            [WDB_SYSCOLLECTOR_NETINFO] = WDB_STMT_SYSCOLLECTOR_NETINFO_CLEAR,
                            [WDB_SYSCOLLECTOR_HWINFO] = WDB_STMT_SYSCOLLECTOR_HWINFO_CLEAR,
                            [WDB_SYSCOLLECTOR_OSINFO] = WDB_STMT_SYSCOLLECTOR_OSINFO_CLEAR };

    assert(component < sizeof(INDEXES) / sizeof(int));

    int retval = -1;
    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse checksum range payload: '%s'", wdb->id, payload);
        goto end;
    }

    cJSON * item = cJSON_GetObjectItem(data, "id");

    if (!cJSON_IsNumber(item)) {
        mdebug1("No such string 'id' in JSON payload.");
        goto end;
    }

    long timestamp = item->valuedouble;

    if (wdb_stmt_cache(wdb, INDEXES[component]) == -1) {
        goto end;
    }

    sqlite3_stmt * stmt = wdb->stmt[INDEXES[component]];

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        goto end;
    }

    wdbi_update_completion(wdb, component, timestamp, "");
    retval = 0;

end:
    cJSON_Delete(data);
    return retval;
}

int wdbi_get_last_manager_checksum(wdb_t *wdb, wdb_component_t component, os_sha1 manager_checksum) {
    int result = OS_INVALID;

    if (wdb_stmt_cache(wdb, WDB_STMT_SYNC_GET_INFO) == -1) {
        mdebug1("Cannot cache statement");
        return result;
    }

    sqlite3_stmt * stmt = wdb->stmt[WDB_STMT_SYNC_GET_INFO];
    sqlite3_bind_text(stmt, 1, COMPONENT_NAMES[component], -1, NULL);

    cJSON* j_sync_info = wdb_exec_stmt(stmt);
    if (!j_sync_info) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
        return result;
    }

    cJSON* j_last_checksum = cJSON_GetObjectItem(j_sync_info->child, "last_manager_checksum");
    if (cJSON_IsString(j_last_checksum)) {
        strncpy(manager_checksum, cJSON_GetStringValue(j_last_checksum), sizeof(os_sha1));
        result = OS_SUCCESS;
    }

    cJSON_Delete(j_sync_info);
    return result;
}
