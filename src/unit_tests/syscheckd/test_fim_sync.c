/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wrappers/common.h"
#include "../syscheckd/syscheck.h"
#include "../syscheckd/fim_db.h"

/* Globals */
extern long fim_sync_cur_id;
extern w_queue_t * fim_sync_queue;

/* Auxiliar structs */
typedef struct __json_payload_s {
    cJSON *payload;
    char *printed_payload;
} json_payload_t;

/* redefinitons/wrapping */
#ifndef TEST_WINAGENT
int __wrap_time() {
    return 1572521857;
}
#endif

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_queue_push_ex(w_queue_t * queue, void * data) {
    int retval = mock();

    check_expected_ptr(queue);
    check_expected(data);

    if(retval != -1)
        free(data);     //  This won't be used, free it

    return retval;
}

int __wrap_fim_db_get_row_path(fdb_t * fim_sql, int mode, char **path) {
    check_expected_ptr(fim_sql);
    check_expected(mode);

    *path = mock_type(char*);

    return mock();
}

int __wrap_fim_db_get_data_checksum(fdb_t *fim_sql, void * arg) {
    check_expected_ptr(fim_sql);

    return mock();
}

char * __wrap_dbsync_check_msg(const char * component, dbsync_msg msg, long id, const char * start, const char * top, const char * tail, const char * checksum) {
    check_expected(component);
    check_expected(msg);
    check_expected(id);
    check_expected(start);
    check_expected(top);
    check_expected(tail);

    return mock_type(char*);
}

void __wrap_fim_send_sync_msg(const char * msg) {
    check_expected(msg);
}


int __wrap_fim_db_get_count_range(fdb_t *fim_sql, char *start, char *top, int *count) {
    check_expected_ptr(fim_sql);
    check_expected(start);
    check_expected(top);

    *count = mock();
    return mock();
}

fim_entry *__wrap_fim_db_get_path(fdb_t *fim_sql, const char *file_path) {
    check_expected_ptr(fim_sql);
    check_expected(file_path);

    return mock_type(fim_entry*);
}

cJSON *__wrap_fim_entry_json(const char * path, fim_entry_data * data) {
    check_expected(path);

    return mock_type(cJSON*);
}

int __wrap_fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                      const long id, const int n) {
    check_expected_ptr(fim_sql);
    check_expected(start);
    check_expected(top);
    check_expected(id);
    check_expected(n);

    return mock();
}

char * __wrap_dbsync_state_msg(const char * component, cJSON * data) {
    check_expected(component);
    check_expected_ptr(data);

    return mock_type(char*);
}

int __wrap_fim_db_get_path_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) {
    check_expected_ptr(fim_sql);
    check_expected(start);
    check_expected(top);
    check_expected(storage);

    *file = mock_type(fim_tmp_file *);

    return mock();
}

int __wrap_fim_db_sync_path_range(fdb_t *fim_sql) {
    check_expected_ptr(fim_sql);

    return mock();
}

#ifdef TEST_WINAGENT // mutex_lock has problems on running with wine
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    return 0;
}
int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    return 0;
}
#endif

/* setup/teardown */
static int setup_group(void **state) {
    #ifdef TEST_WINAGENT
    time_mock_value = 1572521857;
    #endif

    return 0;
}

static int setup_fim_sync_queue(void **state) {
    fim_sync_queue = queue_init(10);

    return 0;
}

static int teardown_fim_sync_queue(void **state) {
    queue_free(fim_sync_queue);

    fim_sync_queue = NULL;

    return 0;
}

static int setup_json_payload(void **state) {
    json_payload_t *json_payload = calloc(1, sizeof(json_payload_t));
    const static char *text_payload =
        "{"
            "\"id\": 1234,"
            "\"begin\": \"start\","
            "\"end\": \"top\""
        "}";

    if(json_payload == NULL)
        return -1;

    json_payload->payload = cJSON_Parse(text_payload);

    if(json_payload->payload == NULL)
        return -1;

    json_payload->printed_payload = cJSON_PrintUnformatted(json_payload->payload);

    if(json_payload->printed_payload == NULL)
        return -1;

    *state = json_payload;
    return 0;
}

static int teardown_json_payload(void **state) {
    json_payload_t *json_payload = *state;

    cJSON_Delete(json_payload->payload);
    free(json_payload->printed_payload);
    free(json_payload);

    return 0;
}

/* tests */
/* fim_sync_push_msg */
static void test_fim_sync_push_msg_success(void **state) {
    char *msg = "This is a mock message, it won't go anywhere";

    expect_value(__wrap_queue_push_ex, queue, fim_sync_queue);
    expect_string(__wrap_queue_push_ex, data, msg);
    will_return(__wrap_queue_push_ex, 0);

    fim_sync_push_msg(msg);
}

static void test_fim_sync_push_msg_queue_full(void **state) {
    char *msg = "This is a mock message, it won't go anywhere";

    expect_value(__wrap_queue_push_ex, queue, fim_sync_queue);
    expect_string(__wrap_queue_push_ex, data, msg);
    will_return(__wrap_queue_push_ex, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Cannot push a data synchronization message: queue is full.");

    fim_sync_push_msg(msg);
}

static void test_fim_sync_push_msg_no_response(void **state) {
    expect_string(__wrap__mwarn, formatted_msg,
        "A data synchronization response was received before sending the first message.");

    fim_sync_push_msg("test");
}

/* fim_sync_checksum */
static void test_fim_sync_checksum_first_row_error(void **state) {
    expect_value(__wrap_fim_db_get_row_path, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_FIRST_ROW);
    will_return(__wrap_fim_db_get_row_path, NULL);
    will_return(__wrap_fim_db_get_row_path, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, "(6706): Couldn't get FIRST row's path.");

    fim_sync_checksum();
}

static void test_fim_sync_checksum_last_row_error(void **state) {
    expect_value_count(__wrap_fim_db_get_row_path, fim_sql, syscheck.database, 2);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_FIRST_ROW);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_LAST_ROW);
    will_return(__wrap_fim_db_get_row_path, NULL);
    will_return(__wrap_fim_db_get_row_path, FIMDB_OK);
    will_return(__wrap_fim_db_get_row_path, NULL);
    will_return(__wrap_fim_db_get_row_path, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, "(6706): Couldn't get LAST row's path.");

    fim_sync_checksum();
}

static void test_fim_sync_checksum_checksum_error(void **state) {
    expect_value_count(__wrap_fim_db_get_row_path, fim_sql, syscheck.database, 2);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_FIRST_ROW);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_LAST_ROW);
    will_return(__wrap_fim_db_get_row_path, NULL);
    will_return(__wrap_fim_db_get_row_path, FIMDB_OK);
    will_return(__wrap_fim_db_get_row_path, NULL);
    will_return(__wrap_fim_db_get_row_path, FIMDB_OK);

    expect_value(__wrap_fim_db_get_data_checksum, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_get_data_checksum, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, FIM_DB_ERROR_CALC_CHECKSUM);

    fim_sync_checksum();
}

static void test_fim_sync_checksum_empty_db(void **state) {
    expect_value_count(__wrap_fim_db_get_row_path, fim_sql, syscheck.database, 2);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_FIRST_ROW);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_LAST_ROW);
    will_return(__wrap_fim_db_get_row_path, NULL);
    will_return(__wrap_fim_db_get_row_path, FIMDB_OK);
    will_return(__wrap_fim_db_get_row_path, NULL);
    will_return(__wrap_fim_db_get_row_path, FIMDB_OK);

    expect_value(__wrap_fim_db_get_data_checksum, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_get_data_checksum, FIMDB_OK);

    expect_string(__wrap_dbsync_check_msg, component, "syscheck");
    expect_value(__wrap_dbsync_check_msg, msg, INTEGRITY_CLEAR);
    expect_value(__wrap_dbsync_check_msg, id, 1572521857);
    expect_value(__wrap_dbsync_check_msg, start, NULL);
    expect_value(__wrap_dbsync_check_msg, top, NULL);
    expect_value(__wrap_dbsync_check_msg, tail, NULL);
    will_return(__wrap_dbsync_check_msg, strdup("A mock message"));

    expect_string(__wrap_fim_send_sync_msg, msg, "A mock message");

    fim_sync_checksum();
}
static void test_fim_sync_checksum_success(void **state) {
    expect_value_count(__wrap_fim_db_get_row_path, fim_sql, syscheck.database, 2);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_FIRST_ROW);
    expect_value(__wrap_fim_db_get_row_path, mode, FIM_LAST_ROW);
    will_return(__wrap_fim_db_get_row_path, strdup("start"));
    will_return(__wrap_fim_db_get_row_path, FIMDB_OK);
    will_return(__wrap_fim_db_get_row_path, strdup("stop"));
    will_return(__wrap_fim_db_get_row_path, FIMDB_OK);

    expect_value(__wrap_fim_db_get_data_checksum, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_get_data_checksum, FIMDB_OK);

    expect_string(__wrap_dbsync_check_msg, component, "syscheck");
    expect_value(__wrap_dbsync_check_msg, msg, INTEGRITY_CHECK_GLOBAL);
    expect_value(__wrap_dbsync_check_msg, id, 1572521857);
    expect_string(__wrap_dbsync_check_msg, start, "start");
    expect_string(__wrap_dbsync_check_msg, top, "stop");
    expect_value(__wrap_dbsync_check_msg, tail, NULL);
    will_return(__wrap_dbsync_check_msg, strdup("A mock message"));

    expect_string(__wrap_fim_send_sync_msg, msg, "A mock message");

    fim_sync_checksum();
}

/* fim_sync_checksum_split */
static void test_fim_sync_checksum_split_get_count_range_error(void **state) {
    expect_value(__wrap_fim_db_get_count_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_count_range, start, "start");
    expect_string(__wrap_fim_db_get_count_range, top, "top");
    will_return(__wrap_fim_db_get_count_range, 0);
    will_return(__wrap_fim_db_get_count_range, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, "(6703): Couldn't get range size between 'start' and 'top'");

    fim_sync_checksum_split("start", "top", 1234);
}

static void test_fim_sync_checksum_split_range_size_0(void **state) {
    expect_value(__wrap_fim_db_get_count_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_count_range, start, "start");
    expect_string(__wrap_fim_db_get_count_range, top, "top");
    will_return(__wrap_fim_db_get_count_range, 0);
    will_return(__wrap_fim_db_get_count_range, FIMDB_OK);

    fim_sync_checksum_split("start", "top", 1234);
}

static void test_fim_sync_checksum_split_range_size_1(void **state) {
    fim_entry *mock_entry = calloc(1, sizeof(fim_entry)); // To be freed by fim_sync_checksum_split

    if(mock_entry == NULL)
        fail();

    expect_value(__wrap_fim_db_get_count_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_count_range, start, "start");
    expect_string(__wrap_fim_db_get_count_range, top, "top");
    will_return(__wrap_fim_db_get_count_range, 1);
    will_return(__wrap_fim_db_get_count_range, FIMDB_OK);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "start");
    will_return(__wrap_fim_db_get_path, mock_entry);

    expect_string(__wrap_fim_entry_json, path, "start");
    will_return(__wrap_fim_entry_json, (cJSON*)2345);

    expect_string(__wrap_dbsync_state_msg, component, "syscheck");
    expect_value(__wrap_dbsync_state_msg, data, 2345);
    will_return(__wrap_dbsync_state_msg, strdup("A mock message"));

    expect_string(__wrap_fim_send_sync_msg, msg, "A mock message");

    fim_sync_checksum_split("start", "top", 1234);
}

static void test_fim_sync_checksum_split_range_size_1_get_path_error(void **state) {
    expect_value(__wrap_fim_db_get_count_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_count_range, start, "start");
    expect_string(__wrap_fim_db_get_count_range, top, "top");
    will_return(__wrap_fim_db_get_count_range, 1);
    will_return(__wrap_fim_db_get_count_range, FIMDB_OK);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "start");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_string(__wrap__merror, formatted_msg, "(6704): Couldn't get path of 'start'");

    fim_sync_checksum_split("start", "top", 1234);
}

static void test_fim_sync_checksum_split_range_size_default(void **state) {
    expect_value(__wrap_fim_db_get_count_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_count_range, start, "start");
    expect_string(__wrap_fim_db_get_count_range, top, "top");
    will_return(__wrap_fim_db_get_count_range, 2);
    will_return(__wrap_fim_db_get_count_range, FIMDB_OK);

    expect_value(__wrap_fim_db_data_checksum_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_data_checksum_range, start, "start");
    expect_string(__wrap_fim_db_data_checksum_range, top, "top");
    expect_value(__wrap_fim_db_data_checksum_range, id, 1234);
    expect_value(__wrap_fim_db_data_checksum_range, n, 2);
    will_return(__wrap_fim_db_data_checksum_range, 0);

    fim_sync_checksum_split("start", "top", 1234);
}

/* fim_sync_send_list */
static void test_fim_sync_send_list_sync_path_range_error(void **state) {
    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "start");
    expect_string(__wrap_fim_db_get_path_range, top, "top");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, FIM_DB_ERROR_SYNC_DB);

    fim_sync_send_list("start", "top");
}

static void test_fim_sync_send_list_success(void **state) {
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->elements = 1;

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "start");
    expect_string(__wrap_fim_db_get_path_range, top, "top");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, file);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    expect_value(__wrap_fim_db_sync_path_range, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_sync_path_range, FIMDB_OK);

    fim_sync_send_list("start", "top");

    free(file);
}

/* fim_sync_dispatch */
static void test_fim_sync_dispatch_null_payload(void **state) {
    expect_assert_failure(fim_sync_dispatch(NULL));
}

static void test_fim_sync_dispatch_no_argument(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "(6312): Data synchronization command 'no_argument' with no argument.");

    fim_sync_dispatch("no_argument");
}

static void test_fim_sync_dispatch_invalid_argument(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "invalid_json %.3s", json_payload->printed_payload);

    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: '{\"i'");

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_id_not_number(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    cJSON_DeleteItemFromObject(json_payload->payload, "id");
    cJSON_AddStringToObject(json_payload->payload, "id", "invalid");

    free(json_payload->printed_payload);

    json_payload->printed_payload = cJSON_PrintUnformatted(json_payload->payload);

    if(json_payload->printed_payload == NULL)
        fail();

    snprintf(payload, OS_MAXSTR, "invalid_id %s", json_payload->printed_payload);

    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: '{\"begin\":\"start\",\"end\":\"top\",\"id\":\"invalid\"}'");

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_drop_message(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "drop_message %s", json_payload->printed_payload);

    fim_sync_cur_id = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "(6316): Dropping message with id (1234) greater than global id (0)");

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_no_begin_object(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    cJSON_DeleteItemFromObject(json_payload->payload, "begin");

    free(json_payload->printed_payload);

    json_payload->printed_payload = cJSON_PrintUnformatted(json_payload->payload);

    if(json_payload->printed_payload == NULL)
        fail();

    snprintf(payload, OS_MAXSTR, "no_begin %s", json_payload->printed_payload);

    fim_sync_cur_id = 1235;

    expect_string(__wrap__mdebug1, formatted_msg, "(6315): Setting global ID back to lower message ID (1234)");
    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: '{\"id\":1234,\"end\":\"top\"}'");

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_checksum_fail(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "checksum_fail %s", json_payload->printed_payload);

    fim_sync_cur_id = 1234;

    // Inside fim_sync_checksum_split
    expect_value(__wrap_fim_db_get_count_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_count_range, start, "start");
    expect_string(__wrap_fim_db_get_count_range, top, "top");
    will_return(__wrap_fim_db_get_count_range, 0);
    will_return(__wrap_fim_db_get_count_range, FIMDB_OK);

    fim_sync_dispatch(payload);
}

static void test_fim_sync_dispatch_no_data(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "no_data %s", json_payload->printed_payload);

    fim_sync_cur_id = 1234;

    // Inside fim_sync_send_list
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->elements = 1;

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "start");
    expect_string(__wrap_fim_db_get_path_range, top, "top");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, file);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    expect_value(__wrap_fim_db_sync_path_range, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_sync_path_range, FIMDB_OK);

    fim_sync_dispatch(payload);

    free(file);
}

static void test_fim_sync_dispatch_unwknown_command(void **state) {
    json_payload_t *json_payload = *state;
    char payload[OS_MAXSTR];

    snprintf(payload, OS_MAXSTR, "unknown %s", json_payload->printed_payload);

    fim_sync_cur_id = 1234;

    // Inside fim_sync_send_list
    expect_string(__wrap__mdebug1, formatted_msg, "(6313): Unknown data synchronization command: 'unknown'");

    fim_sync_dispatch(payload);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_sync_push */
        cmocka_unit_test_setup_teardown(test_fim_sync_push_msg_success, setup_fim_sync_queue, teardown_fim_sync_queue),
        cmocka_unit_test_setup_teardown(test_fim_sync_push_msg_queue_full, setup_fim_sync_queue, teardown_fim_sync_queue),
        cmocka_unit_test(test_fim_sync_push_msg_no_response),

        /* fim_sync_checksum */
        cmocka_unit_test(test_fim_sync_checksum_first_row_error),
        cmocka_unit_test(test_fim_sync_checksum_last_row_error),
        cmocka_unit_test(test_fim_sync_checksum_checksum_error),
        cmocka_unit_test(test_fim_sync_checksum_empty_db),
        cmocka_unit_test(test_fim_sync_checksum_success),

        /* fim_sync_checksum_split */
        cmocka_unit_test(test_fim_sync_checksum_split_get_count_range_error),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_0),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_1),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_1_get_path_error),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_default),

        /* fim_sync_send_list */
        cmocka_unit_test(test_fim_sync_send_list_sync_path_range_error),
        cmocka_unit_test(test_fim_sync_send_list_success),

        /* fim_sync_dispatch */
        cmocka_unit_test(test_fim_sync_dispatch_null_payload),
        cmocka_unit_test(test_fim_sync_dispatch_no_argument),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_invalid_argument, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_id_not_number, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_drop_message, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_no_begin_object, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_checksum_fail, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_no_data, setup_json_payload, teardown_json_payload),
        cmocka_unit_test_setup_teardown(test_fim_sync_dispatch_unwknown_command, setup_json_payload, teardown_json_payload),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
