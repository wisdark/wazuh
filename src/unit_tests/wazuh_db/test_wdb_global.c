
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "wazuhdb_op.h"

extern void __real_cJSON_Delete(cJSON *item);

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("global",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

/* Tests wdb_global_get_agent_labels */

void test_wdb_global_get_agent_labels_transaction_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_labels_cache_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_labels_bind_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_labels_exec_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_labels_success(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_ptr_equal(output, (cJSON*)1);
}

/* Tests wdb_global_del_agent_labels */

void test_wdb_global_del_agent_labels_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_del_agent_labels_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_del_agent_labels_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_del_agent_labels_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_del_agent_labels_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_set_agent_label */

void test_wdb_global_set_agent_label_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_value");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_value");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_value");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_set_sync_status */

void test_wdb_global_set_sync_status_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_sync_agent_info_get */

void test_wdb_global_sync_agent_info_get_transaction_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "Cannot begin transaction");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_sync_agent_info_get_cache_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "Cannot cache statement");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_sync_agent_info_get_bind_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "Cannot bind sql statement");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_sync_agent_info_get_no_agents(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_function_call_any(__wrap_cJSON_Delete);

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "[]");
    os_free(output);
    assert_int_equal(result, WDBC_OK);
}

void test_wdb_global_sync_agent_info_get_success(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
    cJSON *json_output = NULL;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    cJSON *json_labels = NULL;
    cJSON *json_label = NULL;
    int agent_id = 10;

    root = cJSON_CreateArray();
    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent,"test_field", "test_value");
    cJSON_AddItemToArray(root, json_agent);

    will_return_count(__wrap_wdb_begin2, 1, -1);
    will_return_count(__wrap_wdb_stmt_cache, 1, -1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_get_agent_labels()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_global_set_sync_status()
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);
    expect_function_call_any(__wrap_cJSON_Delete);

    // Required for wdb_get_agent_labels()
    json_labels = cJSON_CreateArray();
    json_label = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_label, "id", agent_id);
    cJSON_AddStringToObject(json_label,"key", "test_key");
    cJSON_AddStringToObject(json_label,"value", "test_value");
    cJSON_AddItemToArray(json_labels, json_label);
    will_return(__wrap_wdb_exec_stmt, json_labels);

    // Required for wdb_global_set_sync_status()
    will_return(__wrap_wdb_step, SQLITE_DONE);

    // No more agents
    will_return(__wrap_wdb_exec_stmt, NULL);

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "[{\"id\":10,\"test_field\":\"test_value\",\"labels\":[{\"id\":10,\"key\":\"test_key\",\"value\":\"test_value\"}]}]");
    os_free(output);
    __real_cJSON_Delete(json_output);
    __real_cJSON_Delete(root);
    assert_int_equal(result, WDBC_OK);
}

void test_wdb_global_sync_agent_info_get_sync_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    cJSON *json_labels = NULL;
    int agent_id = 10;

    root = cJSON_CreateArray();
    cJSON_AddItemToArray(root, json_agent = cJSON_CreateObject());
    cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(agent_id));

    will_return_count(__wrap_wdb_begin2, 1, -1);
    will_return_count(__wrap_wdb_stmt_cache, 1, -1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_get_agent_labels()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_global_set_sync_status()
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);
    expect_function_call_any(__wrap_cJSON_Delete);

    // Required for wdb_get_agent_labels()
    json_labels = cJSON_CreateArray();
    will_return(__wrap_wdb_exec_stmt, json_labels);

    // Required for wdb_global_set_sync_status()
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "Cannot set sync_status for agent 10");

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "Cannot set sync_status for agent 10");
    os_free(output);
    __real_cJSON_Delete(root);
    __real_cJSON_Delete(json_labels);
    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_sync_agent_info_get_full(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    cJSON *json_labels = NULL;
    cJSON *json_label = NULL;
    int agent_id = 10;

    root = cJSON_CreateArray();
    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    // Creating a cJSON array bigger than WDB_MAX_RESPONSE_SIZE
    for(int i = 0; i < 2500; i++){
        cJSON_AddStringToObject(json_agent,"test_field", "test_value");
    }
    cJSON_AddItemToArray(root, json_agent);

    will_return_count(__wrap_wdb_begin2, 1, -1);
    will_return_count(__wrap_wdb_stmt_cache, 1, -1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_get_agent_labels()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);
    expect_function_call_any(__wrap_cJSON_Delete);

    // Required for wdb_get_agent_labels()
    json_labels = cJSON_CreateArray();
    json_label = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_label, "id", 1);
    cJSON_AddStringToObject(json_label,"key", "test_key");
    cJSON_AddStringToObject(json_label,"value", "test_value");
    cJSON_AddItemToArray(json_labels, json_label);
    will_return(__wrap_wdb_exec_stmt, json_labels);

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "[]");
    os_free(output);
    __real_cJSON_Delete(root);
    assert_int_equal(result, WDBC_DUE);
}

/* Tests wdb_global_sync_agent_info_set */

void test_wdb_global_sync_agent_info_set_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", 1);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);

    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
    int agent_id = 10;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);
    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
    int agent_id = 10;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);
    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
    int agent_id = 10;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);
    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
    int agent_id = 10;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);
    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_insert_agent */

void test_wdb_global_insert_agent_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = NULL;
    char *ip = NULL;
    char *register_ip = NULL;
    char *internal_key = NULL;
    char *group = NULL;
    int date_add = 0;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = NULL;
    char *ip = NULL;
    char *register_ip = NULL;
    char *internal_key = NULL;
    char *group = NULL;
    int date_add = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind4_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind5_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind6_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, date_add);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind7_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, date_add);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, date_add);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, date_add);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_name */

void test_wdb_global_update_agent_name_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_version */

void test_wdb_global_update_agent_version_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = NULL;
    const char *os_version = NULL;
    const char *os_major = NULL;
    const char *os_minor = NULL;
    const char *os_codename = NULL;
    const char *os_platform = NULL;
    const char *os_build = NULL;
    const char *os_uname = NULL;
    const char *os_arch = NULL;
    const char *version = NULL;
    const char *config_sum = NULL;
    const char *merged_sum = NULL;
    const char *manager_host = NULL;
    const char *node_name = NULL;
    const char *agent_ip = NULL;
    const char *connection_status = NULL;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = NULL;
    const char *os_version = NULL;
    const char *os_major = NULL;
    const char *os_minor = NULL;
    const char *os_codename = NULL;
    const char *os_platform = NULL;
    const char *os_build = NULL;
    const char *os_uname = NULL;
    const char *os_arch = NULL;
    const char *version = NULL;
    const char *config_sum = NULL;
    const char *merged_sum = NULL;
    const char *manager_host = NULL;
    const char *node_name = NULL;
    const char *agent_ip = NULL;
    const char *connection_status = NULL;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind4_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind5_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind6_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind7_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind8_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind9_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind10_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind11_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind12_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind13_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind14_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind15_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind16_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind17_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind18_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 18);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 18);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 18);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_keepalive */

void test_wdb_global_update_agent_keepalive_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_connection_status */

void test_wdb_global_update_agent_connection_status_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_delete_agent */

void test_wdb_global_delete_agent_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_select_agent_name */

void test_wdb_global_select_agent_name_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_bind_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_select_agent_group */

void test_wdb_global_select_agent_group_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_bind_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_select_groups */

void test_wdb_global_select_groups_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_select_groups(data->wdb);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_select_agent_keepalive */

void test_wdb_global_select_agent_keepalive_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_bind1_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_bind2_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_bind3_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_find_agent */

void test_wdb_global_find_agent_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_bind1_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_bind2_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_bind3_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_update_agent_group */

void test_wdb_global_update_agent_group_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *agt_group = "test_group";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_group(data->wdb, 1, agt_group);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_group_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *agt_group = "test_group";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_group(data->wdb, 1, agt_group);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_group_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *agt_group = "test_group";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, agt_group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_group(data->wdb, 1, agt_group);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_group_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *agt_group = "test_group";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, agt_group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_group(data->wdb, 1, agt_group);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_group_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *agt_group = "test_group";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, agt_group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_update_agent_group(data->wdb, 1, agt_group);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_group_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *agt_group = "test_group";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, agt_group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_update_agent_group(data->wdb, 1, agt_group);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_find_group */

void test_wdb_global_find_group_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_find_group(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_global_find_group_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_find_group(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_global_find_group_bind_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_find_group(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_global_find_group_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_find_group(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_global_find_group_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_find_group(data->wdb, group_name);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_insert_agent_group */

void test_wdb_global_insert_agent_group_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_insert_agent_belong */

void test_wdb_global_insert_agent_belong_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id_agent);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id_agent);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id_agent);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_delete_group_belong */

void test_wdb_global_delete_group_belong_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_delete_group_belong(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_belong_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_delete_group_belong(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_belong_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_delete_group_belong(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_belong_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_delete_group_belong(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_belong_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_delete_group_belong(data->wdb, group_name);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_delete_group */

void test_wdb_global_delete_group_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_delete_agent_belong */

void test_wdb_global_delete_agent_belong_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_belong_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_belong_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_belong_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_belong_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_get_agent_info */

void test_wdb_global_get_agent_info_transaction_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_info_cache_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_info_bind_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_info_exec_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_info_success(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_ptr_equal(output, (cJSON*)1);
}

/* Tests wdb_global_get_agents_to_disconnect */

void test_wdb_global_get_agents_to_disconnect_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_bind1_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_bind2_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    int keepalive = 0;
    const char *sync_status = "synced";
    cJSON* root = cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);
    //Setting agents as disconnected
    for (int i=0; i<agents_amount; i++){
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, "disconnected");
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_text, pos, 2);
        expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 3);
        expect_in_range(__wrap_sqlite3_bind_int, value, 0, agents_amount);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_step, SQLITE_DONE);
    }

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_OK);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_to_disconnect_due(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";
    cJSON* root = cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ROW);
    will_return(__wrap_wdb_exec_stmt_sized, root);
    //Setting agents as disconnected
    for (int i=0; i<agents_amount; i++){
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, "disconnected");
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_text, pos, 2);
        expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 3);
        expect_in_range(__wrap_sqlite3_bind_int, value, 0, agents_amount);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_step, SQLITE_DONE);
    }

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_DUE);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_to_disconnect_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 0;
    const char *sync_status = "synced";

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_invalid_elements(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";
    cJSON* root = cJSON_CreateArray();
    cJSON* json_agent = cJSON_CreateObject();
    cJSON_AddItemToArray(root, json_agent);

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);
    //Element error
    expect_string(__wrap__merror, formatted_msg, "Invalid element returned by disconnect query");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_to_disconnect_update_status_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";
    cJSON* root = cJSON_CreateArray();
    cJSON* json_agent = cJSON_CreateObject();
    cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(10));
    cJSON_AddItemToArray(root, json_agent);

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);
    //Disconnect query error
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__merror, formatted_msg, "Cannot set connection_status for agent 10");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

/* Tests wdb_global_get_all_agents */

void test_wdb_global_get_all_agents_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_all_agents_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_all_agents_bind_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_all_agents_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    cJSON* root = cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_OK);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_all_agents_due(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    cJSON* root = cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);

    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ROW);
    will_return(__wrap_wdb_exec_stmt_sized, root);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_DUE);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_all_agents_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

/* Tests wdb_global_reset_agents_connection */

void test_wdb_global_reset_agents_connection_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_connection_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_connection_bind_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_step_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_connection_success(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_get_agents_by_connection_status */

void test_wdb_global_get_agents_by_connection_status_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_bind1_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_bind2_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    const char connection_status[] = "active";
    cJSON* root = cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

    assert_int_equal(status, WDBC_OK);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_by_connection_status_due(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    const char connection_status[] = "active";
    cJSON* root = cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ROW);
    will_return(__wrap_wdb_exec_stmt_sized, root);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

    assert_int_equal(status, WDBC_DUE);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_by_connection_status_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    //Executing statement
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

int main()
{
    const struct CMUnitTest tests[] = {
        /* Tests wdb_global_get_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_success, test_setup, test_teardown),
        /* Tests wdb_global_del_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_success, test_setup, test_teardown),
        /* Tests wdb_global_set_agent_label */
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_success, test_setup, test_teardown),
        /* Tests wdb_global_set_sync_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_success, test_setup, test_teardown),
        /* Tests wdb_global_sync_agent_info_get */
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_no_agents, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_sync_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_full, test_setup, test_teardown),
        /* Tests wdb_global_sync_agent_info_set */
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_success, test_setup, test_teardown),
        /* Tests wdb_global_insert_agent */
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind4_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind5_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind6_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind7_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_version */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind4_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind5_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind6_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind7_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind8_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind9_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind10_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind11_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind12_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind13_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind14_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind15_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind16_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind17_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind18_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_success, test_setup, test_teardown),
        /* Tests wdb_global_delete_agent */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_success, test_setup, test_teardown),
        /* Tests wdb_global_select_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_success, test_setup, test_teardown),
        /* Tests wdb_global_select_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_global_select_groups */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_success, test_setup, test_teardown),
        /* Tests wdb_global_select_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_success, test_setup, test_teardown),
        /* Tests wdb_global_find_agent */
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_group_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_group_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_group_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_global_find_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_success, test_setup, test_teardown),
        /* Tests wdb_global_insert_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_global_insert_agent_belong */
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_success, test_setup, test_teardown),
        /* Tests wdb_global_delete_group_belong */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_belong_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_belong_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_belong_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_belong_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_belong_success, test_setup, test_teardown),
        /* Tests wdb_global_delete_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_success, test_setup, test_teardown),
        /* Tests wdb_global_delete_agent_belong */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agents_to_disconnect */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_update_status_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_invalid_elements, test_setup, test_teardown),
        /* Tests wdb_global_get_all_agents */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_err, test_setup, test_teardown),
        /* Tests wdb_global_reset_agents_connection */
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agents_by_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_err, test_setup, test_teardown),
        };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
