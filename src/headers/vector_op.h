/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 19, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef VECTOR_OP_H
#define VECTOR_OP_H

typedef struct {
    char **vector;
    int used;
    int size;
} W_Vector;


W_Vector *W_Vector_init(int initialSize);


void W_Vector_insert(W_Vector *v, const char *element);


const char *W_Vector_get(W_Vector *v, int position);


int W_Vector_length(W_Vector *v);


void W_Vector_free(W_Vector *v);

// Returns 1 if the element is duplicated, 0 otherwise.
int W_Vector_insert_unique(W_Vector *v, const char *element);

#endif /* VECTOR_OP_H */
