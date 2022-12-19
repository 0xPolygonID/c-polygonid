#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <sys/errno.h>
#include "../ios/libpolygonid-darwin-arm64.h"

char *
read_file(char *path) {
    char *buffer = NULL;

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error opening file %s: %s\n", path, strerror(errno));
        return NULL;
    }

    int r = fseek(f, 0, SEEK_END);
    if (r) {
        fprintf(stderr, "Error seeking to end of file %s: %s\n", path, strerror(errno));
        goto cleanup;
    }

    size_t sz = ftell(f);
    if (!sz) {
        goto cleanup;
    }

    r = fseek(f, 0, SEEK_SET);
    if (r) {
        fprintf(stderr, "Error seeking to begin of file %s: %s\n", path, strerror(errno));
        goto cleanup;
    }

    buffer = malloc(sz + 1);
    if (!buffer) {
        fprintf(stderr, "Error allocating memory for file %s: %s\n", path, strerror(errno));
        goto cleanup;
    }

    r = fread(buffer, sz, 1, f);
    if (!r) {
        fprintf(stderr, "Error reading file %s: %s\n", path, strerror(errno));
        goto cleanup;
    }

    buffer[sz] = 0;

cleanup:
    r = fclose(f);
    if (r != 0) {
        fprintf(stderr, "Error closing file %s: %s\n", path, strerror(errno));
        if (buffer) {
            free(buffer);
        }
        return NULL;
    }

    return buffer;
}

void
consume_status(PLGNStatus *status, char *msg) {
  if (status == NULL) {
        printf("status is NULL\n");
        return;
  }

  char *error_msg;
  if (msg == NULL) {
        error_msg = "error message is empty";
  } else {
        error_msg = msg;
  }

  char *status_msg;
  if (status->error_msg == NULL) {
        status_msg = "status message is empty";
  } else {
        status_msg = status->error_msg;
  }

  printf("[code: %i] %s (%s)\n", status->status, status_msg, error_msg);

  PLGNFreeStatus(status);
}
