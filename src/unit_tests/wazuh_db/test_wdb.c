/*
 * Copyright (C) 2015, Wazuh Inc.
 * March, 2021.
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
#include <string.h>
#include <stdlib.h>

#include "wazuh_db/wdb.h"
#include "wazuhdb_op.h"
#include "hash_op.h"

#include "../wrappers/common.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/libc/string_wrappers.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

/* setup/teardown */

int setup_wdb(void **state) {
    test_mode = 1;
    open_dbs = __real_OSHash_Create();
    if (open_dbs == NULL) {
        return -1;
    }
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    init_data->wdb->stmt[0] = (sqlite3_stmt*)1;
    *state = init_data;
    return 0;
}

int teardown_wdb(void **state) {
    test_mode = 0;
    if (open_dbs) {
        OSHash_Free(open_dbs);
        open_dbs = NULL;
    }
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

/* Tests wdb_open_global */

void test_wdb_open_tasks_pool_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, WDB_TASK_NAME);
    will_return(__wrap_OSHash_Get, data->wdb);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_open_tasks();

    assert_int_equal(ret, data->wdb);
}

void test_wdb_open_tasks_create_error(void **state)
{
    wdb_t *ret = NULL;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, WDB_TASK_NAME);
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/tasks/tasks.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Tasks database not found, creating.");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/tasks/tasks.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);

    will_return(__wrap_sqlite3_errmsg, "out of memory");
    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't create SQLite database 'queue/tasks/tasks.db': out of memory");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database 'queue/tasks/tasks.db'");
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_open_tasks();

    assert_null(ret);
}

void test_wdb_open_global_pool_success(void **state)
{
    wdb_t *ret = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, WDB_GLOB_NAME);
    will_return(__wrap_OSHash_Get, data->wdb);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_open_global();

    assert_int_equal(ret, data->wdb);
}

void test_wdb_open_global_create_fail(void **state)
{
    wdb_t *ret = NULL;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, WDB_GLOB_NAME);
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Global database not found, creating.");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    // wdb_create_global
    //// wdb_create_file
    expect_string(__wrap_sqlite3_open_v2, filename, "queue/db/global.db");
    will_return(__wrap_sqlite3_open_v2, NULL);
    expect_value(__wrap_sqlite3_open_v2, flags, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    will_return(__wrap_sqlite3_open_v2, OS_INVALID);

    will_return(__wrap_sqlite3_errmsg, "out of memory");
    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db': out of memory");
    will_return(__wrap_sqlite3_close_v2, OS_SUCCESS);

    expect_string(__wrap__merror, formatted_msg, "Couldn't create SQLite database 'queue/db/global.db'");
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = wdb_open_global();

    assert_null(ret);
}

/* Tests db_exec_row_stmt */

void test_wdb_exec_row_stmt_one_int(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_value(__wrap_sqlite3_column_double, iCol, 0);
    will_return(__wrap_sqlite3_column_double, json_value);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);

    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_string_equal(result->child->string, json_str);
    assert_int_equal(result->child->valuedouble, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_row_stmt_multiple_int(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const int columns = 10;
    char json_strs[columns][OS_SIZE_256];
    for (int column=0; column < columns; column++){
        snprintf(json_strs[column], OS_SIZE_256, "COLUMN%d",column);
    }

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, columns);
    for (int column=0; column < columns; column++){
        expect_value(__wrap_sqlite3_column_type, i, column);
        will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
        expect_value(__wrap_sqlite3_column_name, N, column);
        will_return(__wrap_sqlite3_column_name, json_strs[column]);
        expect_value(__wrap_sqlite3_column_double, iCol, column);
        will_return(__wrap_sqlite3_column_double, column);
    }

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);

    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    cJSON* json_column = NULL;
    int column = 0;
    cJSON_ArrayForEach(json_column, result) {
        assert_string_equal(json_column->string, json_strs[column]);
        assert_int_equal(json_column->valuedouble, column);
        column++;
    }

    cJSON_Delete(result);
}

void test_wdb_exec_row_stmt_one_text(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    const char*  json_value = "VALUE";

    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_value(__wrap_sqlite3_column_type, i, 0);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_name, N, 0);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, json_value);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);
    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_string_equal(result->child->string, json_str);
    assert_string_equal(result->child->valuestring, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_row_stmt_done(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_DONE);

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);assert_null(result);
    assert_int_equal(status, SQLITE_DONE);
    assert_null(result);
}

void test_wdb_exec_row_stmt_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    int status = 0;
    cJSON* result = wdb_exec_row_stmt(*data->wdb->stmt, &status);
    assert_int_equal(status, SQLITE_ERROR);
    assert_null(result);
}

/* Tests wdb_exec_stmt_sized */

void test_wdb_exec_stmt_sized_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return_count(__wrap_sqlite3_column_count, 1, -1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER,-1);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return_count(__wrap_sqlite3_column_name, json_str, -1);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return_count(__wrap_sqlite3_column_double, json_value, -1);

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, WDB_MAX_RESPONSE_SIZE, &status);

    assert_int_equal(status, SQLITE_DONE);
    assert_non_null(result);
    assert_string_equal(result->child->child->string, json_str);
    assert_int_equal(result->child->child->valuedouble, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_stmt_sized_success_limited(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;
    const int rows = 20;
    const int max_size = 282;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_count(SQLITE_ROW, rows);
    will_return_count(__wrap_sqlite3_column_count, 1, -1);
    expect_any_count(__wrap_sqlite3_column_type, i, -1);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER, -1);
    expect_any_count(__wrap_sqlite3_column_name, N, -1);
    will_return_count(__wrap_sqlite3_column_name, json_str, -1);
    expect_any_count(__wrap_sqlite3_column_double, iCol, -1);
    will_return_count(__wrap_sqlite3_column_double, json_value, -1);

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, max_size, &status);

    assert_int_equal(status, SQLITE_ROW);
    assert_non_null(result);
    assert_int_equal(cJSON_GetArraySize(result), rows-1);

    cJSON_Delete(result);
}

void test_wdb_exec_stmt_sized_invalid_statement(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid SQL statement.");

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(NULL, WDB_MAX_RESPONSE_SIZE, &status);

    assert_int_equal(status, SQLITE_ERROR);
    assert_null(result);
}

void test_wdb_exec_stmt_sized_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    int status = 0;
    cJSON* result = wdb_exec_stmt_sized(*data->wdb->stmt, WDB_MAX_RESPONSE_SIZE, &status);

    assert_int_equal(status, SQLITE_ERROR);
    assert_null(result);

    cJSON_Delete(result);
}

/* Tests wdb_exec_stmt */

void test_wdb_exec_stmt_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char* json_str = "COLUMN";
    double json_value = 10;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return_count(__wrap_sqlite3_column_count, 1, -1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER,-1);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return_count(__wrap_sqlite3_column_name, json_str, -1);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return_count(__wrap_sqlite3_column_double, json_value, -1);

    cJSON* result = wdb_exec_stmt(*data->wdb->stmt);

    assert_non_null(result);
    assert_string_equal(result->child->child->string, json_str);
    assert_int_equal(result->child->child->valuedouble, json_value);

    cJSON_Delete(result);
}

void test_wdb_exec_stmt_invalid_statement(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid SQL statement.");

    cJSON* result = wdb_exec_stmt(NULL);

    assert_null(result);
}

void test_wdb_exec_stmt_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    cJSON* result = wdb_exec_stmt(*data->wdb->stmt);
    assert_null(result);

    cJSON_Delete(result);
}

/* Tests wdb_exec_stmt_silent */

void test_wdb_exec_stmt_silent_success_sqlite_done(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_DONE);

    int result = wdb_exec_stmt_silent(*data->wdb->stmt);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_exec_stmt_silent_success_sqlite_row(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_ROW);

    int result = wdb_exec_stmt_silent(*data->wdb->stmt);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_exec_stmt_silent_invalid(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_sqlite3_step_call(SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    int result = wdb_exec_stmt_silent(*data->wdb->stmt);

    assert_int_equal(result, OS_INVALID);
}

/* Tests wdb_exec_stmt_send */

void test_wdb_exec_stmt_send_single_row_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;
    const char* json_str = "COLUMN";
    double json_value = 10;
    cJSON* j_query_result = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_query_result, json_str, json_value);
    char* str_query_result = cJSON_PrintUnformatted(j_query_result);
    char* command_result = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), command_result);

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return(__wrap_sqlite3_column_double, json_value);
    expect_sqlite3_step_call(SQLITE_DONE);

    os_snprintf(command_result, OS_MAXSTR, "due %s", str_query_result);
    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(command_result));
    expect_string(__wrap_OS_SendSecureTCP, msg, command_result);
    will_return(__wrap_OS_SendSecureTCP, 0);

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SUCCESS);

    cJSON_Delete(j_query_result);
    os_free(str_query_result);
    os_free(command_result);
}

void test_wdb_exec_stmt_send_multiple_rows_success(void **state) {
    int ROWS_RESPONSE = 100;
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;
    const char* json_str = "COLUMN";
    double json_value = 10;
    cJSON* j_query_result = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_query_result, json_str, json_value);
    char* str_query_result = cJSON_PrintUnformatted(j_query_result);
    char* command_result = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), command_result);

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_count(SQLITE_ROW, ROWS_RESPONSE);
    will_return_count(__wrap_sqlite3_column_count, 1, ROWS_RESPONSE);
    expect_any_count(__wrap_sqlite3_column_type, i, ROWS_RESPONSE);
    will_return_count(__wrap_sqlite3_column_type, SQLITE_INTEGER, ROWS_RESPONSE);
    expect_any_count(__wrap_sqlite3_column_name, N, ROWS_RESPONSE);
    will_return_count(__wrap_sqlite3_column_name, json_str, ROWS_RESPONSE);
    expect_any_count(__wrap_sqlite3_column_double, iCol, ROWS_RESPONSE);
    will_return_count(__wrap_sqlite3_column_double, json_value, ROWS_RESPONSE);
    expect_sqlite3_step_call(SQLITE_DONE);

    os_snprintf(command_result, OS_MAXSTR, "due %s", str_query_result);
    expect_value_count(__wrap_OS_SendSecureTCP, sock, peer, ROWS_RESPONSE);
    expect_value_count(__wrap_OS_SendSecureTCP, size, strlen(command_result), ROWS_RESPONSE);
    expect_string_count(__wrap_OS_SendSecureTCP, msg, command_result, ROWS_RESPONSE);
    will_return_count(__wrap_OS_SendSecureTCP, 0, ROWS_RESPONSE);

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SUCCESS);

    cJSON_Delete(j_query_result);
    os_free(str_query_result);
    os_free(command_result);
}

void test_wdb_exec_stmt_send_no_rows_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_DONE);

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_exec_stmt_send_row_size_limit_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;
    const char* json_str = "COLUMN";
    char* json_value = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), json_value);
    memset(json_value,'A',OS_MAXSTR-1);
    cJSON* j_query_result = cJSON_CreateObject();
    cJSON_AddStringToObject(j_query_result, json_str, json_value);
    char* str_query_result = cJSON_PrintUnformatted(j_query_result);

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_any(__wrap_sqlite3_column_text, iCol);
    will_return(__wrap_sqlite3_column_text, json_value);

    will_return(__wrap_sqlite3_sql, "STATEMENT");
    expect_string(__wrap__merror, formatted_msg, "SQL row response for statement STATEMENT is too big to be sent");

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SIZELIM);

    cJSON_Delete(j_query_result);
    os_free(str_query_result);
    os_free(json_value);
}

void test_wdb_exec_stmt_send_socket_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;
    const char* json_str = "COLUMN";
    double json_value = 10;
    cJSON* j_query_result = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_query_result, json_str, json_value);
    char* str_query_result = cJSON_PrintUnformatted(j_query_result);
    char* command_result = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), command_result);

    will_return(__wrap_OS_SetSendTimeout, 0);

    //Calling wdb_exec_row_stmt
    expect_sqlite3_step_call(SQLITE_ROW);
    will_return(__wrap_sqlite3_column_count, 1);
    expect_any(__wrap_sqlite3_column_type, i);
    will_return(__wrap_sqlite3_column_type, SQLITE_INTEGER);
    expect_any(__wrap_sqlite3_column_name, N);
    will_return(__wrap_sqlite3_column_name, json_str);
    expect_any(__wrap_sqlite3_column_double, iCol);
    will_return(__wrap_sqlite3_column_double, json_value);

    os_snprintf(command_result, OS_MAXSTR, "due %s", str_query_result);
    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(command_result));
    expect_string(__wrap_OS_SendSecureTCP, msg, command_result);
    will_return(__wrap_OS_SendSecureTCP, -1);

    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "Socket 1234 error: error (0)");

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SOCKTERR);

    cJSON_Delete(j_query_result);
    os_free(str_query_result);
    os_free(command_result);
}

void test_wdb_exec_stmt_send_timeout_set_err(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int peer = 1234;

    will_return(__wrap_OS_SetSendTimeout, -1);

    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "Socket 1234 error setting timeout: error (0)");

    int result = wdb_exec_stmt_send(*data->wdb->stmt, peer);

    assert_int_equal(result, OS_SOCKTERR);
}

void test_wdb_exec_stmt_send_statement_invalid(void **state) {
    int peer = 1234;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid SQL statement.");

    int result = wdb_exec_stmt_send(NULL, peer);

    assert_int_equal(result, OS_INVALID);
}

/* Tests wdb_init_stmt_in_cache */

void test_wdb_init_stmt_in_cache_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    // wdb_begin2
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_stmt_cache
    will_return(__wrap_sqlite3_reset, SQLITE_OK);
    will_return(__wrap_sqlite3_clear_bindings, SQLITE_OK);

    sqlite3_stmt* result = wdb_init_stmt_in_cache(data->wdb, WDB_STMT_FIM_LOAD);

    assert_non_null(result);
}

void test_wdb_init_stmt_in_cache_invalid_transaction(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    // wdb_begin2
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    sqlite3_stmt* result = wdb_init_stmt_in_cache(data->wdb, 0);

    assert_null(result);
}

void test_wdb_init_stmt_in_cache_invalid_statement(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int STR_SIZE = 48;
    char error_message[STR_SIZE];
    snprintf(error_message, STR_SIZE, "DB(000) SQL statement index (%d) out of bounds", WDB_STMT_SIZE);

    // wdb_begin2
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);
    expect_sqlite3_step_call(SQLITE_DONE);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    // wdb_stmt_cache
    expect_string(__wrap__merror, formatted_msg, error_message);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    sqlite3_stmt* result = wdb_init_stmt_in_cache(data->wdb,WDB_STMT_SIZE);

    assert_null(result);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        //wdb_open_tasks
        cmocka_unit_test_setup_teardown(test_wdb_open_tasks_pool_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_open_tasks_create_error, setup_wdb, teardown_wdb),
        //wdb_open_global
        cmocka_unit_test_setup_teardown(test_wdb_open_global_pool_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_open_global_create_fail, setup_wdb, teardown_wdb),
        //wdb_exec_row_stm
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_one_int, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_multiple_int, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_one_text, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_done, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_row_stmt_error, setup_wdb, teardown_wdb),
        //wdb_exec_stmt
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_invalid_statement, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_error, setup_wdb, teardown_wdb),
        //wdb_exec_stmt_sized
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_success_limited, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_invalid_statement, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_sized_error, setup_wdb, teardown_wdb),
        //wdb_exec_stmt_silent
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_silent_success_sqlite_done, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_silent_success_sqlite_row, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_silent_invalid, setup_wdb, teardown_wdb),
        //wdb_exec_stmt_send
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_single_row_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_multiple_rows_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_no_rows_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_row_size_limit_err, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_socket_err, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_timeout_set_err, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_exec_stmt_send_statement_invalid, setup_wdb, teardown_wdb),
        //wdb_init_stmt_in_cache
        cmocka_unit_test_setup_teardown(test_wdb_init_stmt_in_cache_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_init_stmt_in_cache_invalid_transaction, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_init_stmt_in_cache_invalid_statement, setup_wdb, teardown_wdb)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
