#include "common.h"
#include <stdbool.h>

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
    PLGNStatus *status = NULL;
    bool ok = PLGNAuthV2InputsMarshal(&resp, input, &status);
    if (!ok) {
        consume_status(status, "Error marshaling input");
        ret_val = 1;
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
