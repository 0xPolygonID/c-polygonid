#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../build/libpolygonid-darwin-arm64.h"

char *
read_file(char *path) {
    char *buffer = NULL;

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error opening file %s: %s", path, strerror(errno));
        return NULL;
    }

    int r = fseek(f, 0, SEEK_END);
    if (r) {
        fprintf(stderr, "Error seeking to end of file %s: %s", path, strerror(errno));
        goto cleanup;
    }

    size_t sz = ftell(f);
    if (!sz) {
        goto cleanup;
    }

    r = fseek(f, 0, SEEK_SET);
    if (r) {
        fprintf(stderr, "Error seeking to begin of file %s: %s", path, strerror(errno));
        goto cleanup;
    }

    buffer = malloc(sz + 1);
    if (!buffer) {
        fprintf(stderr, "Error allocating memory for file %s: %s", path, strerror(errno));
        goto cleanup;
    }

    r = fread(buffer, sz, 1, f);
    if (!r) {
        fprintf(stderr, "Error reading file %s: %s", path, strerror(errno));
        goto cleanup;
    }

    buffer[sz] = 0;

cleanup:
    r = fclose(f);
    if (r != 0) {
        fprintf(stderr, "Error closing file %s: %s", path, strerror(errno));
        if (buffer) {
            free(buffer);
        }
        return NULL;
    }

    return buffer;
}

int
main() {
    int ret_val = 0;
    char *input = read_file("auth_v2_inputs_in.json");
    if (!input) {
        ret_val = 1;
        goto cleanup;
    }
    char *want_output = read_file("auth_v2_inputs_out.json");
    if (!want_output) {
        ret_val = 1;
        goto cleanup;
    }
    // remove trailing newline
    want_output[strcspn(want_output, "\n")] = 0;

    char *resp = NULL;
    bool ok = PLGNAuthV2InputsMarshal(&resp, input, NULL);
    if (!ok) {
        ret_val = 1;
        fprintf(stderr, "Error marshaling input");
        goto cleanup;
    }

//    printf("output: %d\n", res);
//    if (resp) {
//        printf("%s\n", resp);
//    }

    ret_val = strcmp(resp, want_output);
    if (ret_val) {
        fprintf(stderr, "result is not equal to expected output\ngot:  %s\nwant: %s\n",
            resp, want_output);
    }

cleanup:
    if (input) {
        free(input);
    }
    if (resp) {
        free(resp);
    }
    if (want_output) {
        free(want_output);
    }
    return ret_val;
}
