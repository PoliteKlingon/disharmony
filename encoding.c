#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "encoding.h"

char *encode(void *data, size_t data_len)
{
    char *res = calloc(data_len * 2 + 1, 1); //for each byte we have two chars plus '\0'
    if (res == NULL) {
        fprintf(stderr, "Not enough memory!\n");
        return NULL;
    }

    u_int8_t *char_data = (u_int8_t *)data;
    u_int8_t current;
    size_t counter = 0;
    for (size_t i = 0; i < data_len; i++) {
         current = char_data[i];
         res[counter] = current / 64 + '#';
         res[counter + 1] = current % 64 + '#';
         counter += 2;
    }
    return res;
}

void *decode(char *data, size_t *data_len)
{
    *data_len = strlen(data) / 2;

    char *res = calloc(*data_len, 1);
    if (res == NULL) {
        fprintf(stderr, "Not enough memory!\n");
        return NULL;
    }

    char current;
    size_t counter = 0;
    for (size_t i = 0; i < *data_len; i++) {
        current = data[counter];
        res[i] = (current - '#') * 64;
        current = data[counter + 1];
        res[i] += current - '#';
        counter += 2;
    }
    return res;
}