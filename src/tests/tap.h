/* TAP format macros. */
#ifndef LIB_TAP_H
#define LIB_TAP_H

static int tap_count;
static int tap_todo;
static int tap_fail;

#define ENDLINE_TEST             \
    {                            \
        if (tap_todo)            \
        {                        \
            printf(" # TODO\n"); \
        }                        \
        else                     \
        {                        \
            printf("\n");        \
        }                        \
    }

#define TAP_TEST_MSG(x, msg, args...)                   \
{                                                       \
    tap_count++;                                        \
    if (!(x)) {                                         \
        if (!tap_todo) {                                \
            tap_fail++;                                 \
        }                                               \
        printf("not ok %*d - ", 2 , tap_count);    \
    }                                                   \
    else {                                              \
        printf("    ok %*d - ", 2 , tap_count);  \
    }                                                   \
    printf(msg, ##args);                                \
    ENDLINE_TEST;                                       \
}

#define TODO tap_todo = 1
#define END_TODO tap_todo = 0

#define TAP_PLAN { printf("1..%d\n", tap_count); }

int tap_summary() {
    if (tap_fail > 0) {
        printf("\n       [ %d TEST FAILED ]\n", tap_fail);
        return 1;
    } else {
        printf("\n      [ ALL TESTS PASSED ]\n");
        return 0;
    }
}

/**
 * Check two integers to determine if X OP Y
 *
 * If not X OP Y, the test fails.
 *
 * @param X integer
 * @param Y integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define _w_assert_int(X, OP, Y)     \
({                                  \
  int _w_x = (X);                   \
  int _w_y = (Y);                   \
  if(!(_w_x OP _w_y)){return 0;}    \
})

/**
 * Check two integers to determine if X == Y
 *
 * If not X == Y, the test fails.
 *
 * @param X integer
 * @param Y integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_int_eq(X, Y)   \
({                              \
    _w_assert_int(X, ==, Y);    \
})

/**
 * Check two integers to determine if X != Y
 *
 * If not X != Y, the test fails.
 *
 * @param X integer
 * @param Y integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_int_ne(X, Y)   \
({                              \
    _w_assert_int(X, !=, Y);    \
})

/**
 * Check two integers to determine if X < Y
 *
 * If not X < Y, the test fails.
 *
 * @param X integer
 * @param Y integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_int_lt(X, Y)   \
({                              \
    _w_assert_int(X, <, Y);     \
})

/**
 * Check two integers to determine if X <= Y
 *
 * If not X <= Y, the test fails.
 *
 * @param X integer
 * @param Y integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_int_le(X, Y)   \
({                              \
    _w_assert_int(X, <=, Y);    \
})

/**
 * Check two integers to determine if X > Y
 *
 * If not X > Y, the test fails.
 *
 * @param X integer
 * @param Y integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_int_gt(X, Y)   \
({                              \
    _w_assert_int(X, >, Y);     \
})

/**
 * Check two integers to determine if X >= Y
 *
 * If not X OP Y, the test fails.
 *
 * @param X integer
 * @param Y integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_int_ge(X, Y)   \
({                              \
    _w_assert_int(X, >=, Y);    \
})


/**
 * Check two unsigned integers to determine if X OP Y
 *
 * If not X OP Y, the test fails.
 *
 * @param X unsigned integer
 * @param Y unsigned integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define _w_assert_uint(X, OP, Y)    \
({                                  \
  unsigned int _w_x = (X);          \
  unsigned int _w_y = (Y);          \
  if(!(_w_x OP _w_y)){return 0;}    \
})

/**
 * Check two unsigned integers to determine if X == Y
 *
 * If not X == Y, the test fails.
 *
 * @param X unsigned integer
 * @param Y unsigned integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_uint_eq(X, Y)      \
({                                  \
    _w_assert_uint(X, ==, Y);       \
})

/**
 * Check two unsigned integers to determine if X != Y
 *
 * If not X != Y, the test fails.
 *
 * @param X unsigned integer
 * @param Y unsigned integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_uint_ne(X, Y)      \
({                                  \
    _w_assert_uint(X, !=, Y);       \
})

/**
 * Check two unsigned integers to determine if X < Y
 *
 * If not X < Y, the test fails.
 *
 * @param X unsigned integer
 * @param Y unsigned integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_uint_lt(X, Y)      \
({                                  \
    _w_assert_uint(X, <, Y);        \
})

/**
 * Check two unsigned integers to determine if X <= Y
 *
 * If not X <= Y, the test fails.
 *
 * @param X unsigned integer
 * @param Y unsigned integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_uint_le(X, Y)      \
({                                  \
    _w_assert_uint(X, <=, Y);       \
})

/**
 * Check two unsigned integers to determine if X > Y
 *
 * If not X > Y, the test fails.
 *
 * @param X unsigned integer
 * @param Y unsigned integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_uint_gt(X, Y)      \
({                                  \
    _w_assert_uint(X, >, Y);        \
})

/**
 * Check two unsigned integers to determine if X >= Y
 *
 * If not X >= Y, the test fails.
 *
 * @param X unsigned integer
 * @param Y unsigned integer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_uint_ge(X, Y)      \
({                                  \
    _w_assert_uint(X, >=, Y);       \
})

/**
 * Check two strings to determine if X OP Y
 *
 * If not X OP Y, the test fails.
 *
 * @param X string
 * @param Y string to compare against X
 * @note If the check fails, the test fails
 *
 */
#define _w_assert_str(X, OP, Y)             \
({                                          \
  const char* _w_x = (X);                   \
  const char* _w_y = (Y);                   \
  if(!(0 OP strcmp(_w_x, _w_y))){return 0;} \
})

/**
 * Check two strings to determine if X == Y
 *
 * If not 0 == strcmp(X,Y), the test fails.
 *
 * @param X string
 * @param Y string to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_str_eq(X, Y)   \
({                              \
    _w_assert_str(X, ==, Y);    \
})

/**
 * Check two strings to determine if X != Y
 *
 * If not 0 != strcmp(X,Y), the test fails.
 *
 * @param X string
 * @param Y string to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_str_ne(X, Y)   \
({                              \
    _w_assert_str(X, !=, Y);    \
})

/**
 * Check two strings to determine if X < Y
 *
 * If not 0 < strcmp(X,Y), the test fails.
 *
 * @param X string
 * @param Y string to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_str_lt(X, Y)   \
({                              \
    _w_assert_str(X, <, Y);     \
})

/**
 * Check two strings to determine if X <= Y
 *
 * If not 0 <= strcmp(X,Y), the test fails.
 *
 * @param X string
 * @param Y string to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_str_le(X, Y)   \
({                              \
    _w_assert_str(X, <=, Y);    \
})

/**
 * Check two strings to determine if X > Y
 *
 * If not 0 > strcmp(X,Y), the test fails.
 *
 * @param X string
 * @param Y string to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_str_gt(X, Y)   \
({                              \
    _w_assert_str(X, >, Y);     \
})

/**
 * Check two strings to determine if X >= Y
 *
 * If not 0 >= strcmp(X,Y), the test fails.
 *
 * @param X string
 * @param Y string to compare against X
 * @note If the check fails, the test fails
 */
#define w_assert_str_ge(X, Y)   \
({                              \
    _w_assert_str(X, >=, Y);    \
})

/**
 * Check two pointers to determine if X OP Y
 *
 * If not X OP Y, the test fails.
 *
 * @param X pointer
 * @param Y pointer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define _w_assert_ptr(X, OP, Y)     \
({                                  \
  const void* _w_x = (X);           \
  const void* _w_y = (Y);           \
  if(!(_w_x OP _w_y)){return 0;}    \
})

/**
 * Check two pointers to determine if X == Y
 *
 * If not X == Y, the test fails.
 *
 * @param X pointer
 * @param Y pointer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_ptr_eq(X, Y)   \
({                              \
    _w_assert_ptr(X, ==, Y);    \
})

/**
 * Check two pointers to determine if X != Y
 *
 * If not X != Y, the test fails.
 *
 * @param X pointer
 * @param Y pointer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_ptr_ne(X, Y)   \
({                              \
    _w_assert_ptr(X, !=, Y);    \
})

/**
 * Check two pointers to determine if X < Y
 *
 * If not X < Y, the test fails.
 *
 * @param X pointer
 * @param Y pointer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_ptr_lt(X, Y)   \
({                              \
    _w_assert_ptr(X, <, Y);     \
})

/**
 * Check two pointers to determine if X <= Y
 *
 * If not X <= Y, the test fails.
 *
 * @param X pointer
 * @param Y pointer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_ptr_le(X, Y)   \
({                              \
    _w_assert_ptr(X, <=, Y);    \
})

/**
 * Check two pointers to determine if X > Y
 *
 * If not X > Y, the test fails.
 *
 * @param X pointer
 * @param Y pointer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_ptr_gt(X, Y)   \
({                              \
    _w_assert_ptr(X, >, Y);     \
})

/**
 * Check two pointers to determine if X >= Y
 *
 * If not X >= Y, the test fails.
 *
 * @param X pointer
 * @param Y pointer to compare against X
 * @note If the check fails, the test fails
 *
 */
#define w_assert_ptr_ge(X, Y)   \
({                              \
    _w_assert_ptr(X, >=, Y);    \
})

#endif /* LIB_TAP_H */
