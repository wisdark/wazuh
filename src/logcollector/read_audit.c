/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"
#include "os_crypto/sha1/sha1_op.h"

#define MAX_CACHE 16
#define MAX_HEADER 64

/* Compile message from cache and send through queue */
static void audit_send_msg(char **cache, int top, const char *file, int drop_it, logtarget * targets) {
    int i;
    size_t n = 0;
    size_t z;
    char message[OS_MAX_LOG_SIZE] = {0};

    for (i = 0; i < top; i++) {
        z = strlen(cache[i]);

        if (n + z + 1 < sizeof(message)) {
            if (n > 0)
                message[n++] = ' ';

            strncat(message + n, cache[i], OS_MAX_LOG_SIZE - 1 - n);
            n += z;
        }

        free(cache[i]);
    }

    if (!drop_it) {
        message[n] = '\0';
        w_msg_hash_queues_push(message, (char *)file, strlen(message) + 1, targets, LOCALFILE_MQ);
    }
}

void *read_audit(logreader *lf, int *rc, int drop_it) {
    char *cache[MAX_CACHE];
    char header[MAX_HEADER] = { '\0' };
    int icache = 0;
    char buffer[OS_MAX_LOG_SIZE];
    char *id;
    char *p;
    size_t z;
    int64_t offset = 0;
    int64_t rbytes = 0;

    int lines = 0;

    *rc = 0;

    /* Obtain context to calculate hash */
    SHA_CTX context;
    offset = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, offset);

    for (offset = w_ftell(lf->fp); can_read() && fgets(buffer, OS_MAX_LOG_SIZE, lf->fp) && (!maximum_lines || lines < maximum_lines) && offset >= 0; offset += rbytes) {
        rbytes = w_ftell(lf->fp) - offset;

        /* Flow control */
        if (rbytes <= 0) {
            break;
        }

        lines++;

        if (buffer[rbytes - 1] == '\n') {
            if (is_valid_context_file) {
                OS_SHA1_Stream(&context, NULL, buffer);
            }

            buffer[rbytes - 1] = '\0';

            if ((int64_t)strlen(buffer) != rbytes - 1)
            {
                mdebug2("Line in '%s' contains some zero-bytes (valid=" FTELL_TT " / total=" FTELL_TT "). Dropping line.", lf->file, FTELL_INT64 strlen(buffer), FTELL_INT64 rbytes - 1);
                continue;
            }
        } else {
            if (rbytes == OS_MAX_LOG_SIZE - 1) {
                // Message too large, discard line
                for (offset += rbytes; fgets(buffer, OS_MAX_LOG_SIZE, lf->fp); offset += rbytes) {
                    rbytes = w_ftell(lf->fp) - offset;

                    /* Flow control */
                    if (rbytes <= 0) {
                        break;
                    }
                    if (is_valid_context_file) {
                        OS_SHA1_Stream(&context, NULL, buffer);
                    }

                    if (buffer[rbytes - 1] == '\n') {
                        break;
                    }
                }
            } else if (feof(lf->fp)) {
                mdebug2("Message not complete. Trying again: '%s'", buffer);

                if (fseek(lf->fp, offset, SEEK_SET) < 0) {
                   merror(FSEEK_ERROR, lf->file, errno, strerror(errno));
                   break;
               }
            }

            break;
        }

        // Extract header: "\.*type=\.* msg=audit(.*):"
        //                                        --

        if (!((id = strstr(buffer, "type=")) && (id = strstr(id + 5, " msg=audit(")) && (p = strstr(id += 11, "): ")))) {
            merror("Discarding audit message because of invalid syntax.");
            break;
        }

        z = p - id;

        if (strncmp(id, header, z)) {
            // Current message belongs to another event: send cached messages
            if (icache > 0)
                audit_send_msg(cache, icache, lf->file, drop_it, lf->log_target);

            // Store current event
            *cache = strdup(buffer);
            icache = 1;
            strncpy(header, id, z < MAX_HEADER ? z : MAX_HEADER - 1);
        } else {
            // The header is the same: store
            if (icache == MAX_CACHE)
                merror("Discarding audit message because cache is full.");
            else
                cache[icache++] = strdup(buffer);
        }
    }

    if (icache > 0)
        audit_send_msg(cache, icache, lf->file, drop_it, lf->log_target);
    if (is_valid_context_file) {
        w_update_file_status(lf->file, offset, &context);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return NULL;
}
