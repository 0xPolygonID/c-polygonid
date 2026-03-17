#include "common.h"
#include <stdbool.h>

// FN is a function that takes no configuration
typedef GoUint8(*FN)(char**, char*, PLGNStatus**);

// FN2 is a function that takes a configuration argument
typedef GoUint8(*FN2)(char**, char*, char*, PLGNStatus**);

typedef struct _TEST_STATUS {
  char *in;
  char *cfg;
  FN fn;
  FN2 fn2;
  GoUint8 expected_ok;
  PLGNStatusCode expected_status_code; // checked only when expected_ok == false
} TEST_STATUS;

TEST_STATUS testCases[] = {
  {
    .in = "testdata/anon_aadhaar_v1_inputs_invalid_signature.json",
    .fn2 = &PLGNW3CCredentialFromAnonAadhaarInputs,
    .expected_ok = false,
    .expected_status_code = PLGNSTATUSCODE_INVALID_AADHAAR_SIGNATURE,
    .cfg = "testdata/new_genesis_id_cfg.json"
  },
  {
    .in = "testdata/anon_aadhaar_v1_inputs_invalid_signature.json",
    .fn2 = &PLGNAGenerateInputs,
    .expected_ok = false,
    .expected_status_code = PLGNSTATUSCODE_INVALID_AADHAAR_SIGNATURE,
    .cfg = "testdata/new_genesis_id_cfg.json"
  }
};

// returns 0 on success, non-0 on failure
int
run_status_test(TEST_STATUS tc) {
  int ret_val = 0;
  char *resp = NULL;
  PLGNStatus *status = NULL;
  char *input = NULL;
  char *cfg = NULL;

  if (tc.fn == NULL && tc.fn2 == NULL) {
    fprintf(stderr, "both fn and fn2 are NULL\n");
    ret_val = 1;
    goto cleanup;
  }

  if (tc.fn != NULL && tc.fn2 != NULL) {
    fprintf(stderr, "both fn and fn2 are set\n");
    ret_val = 1;
    goto cleanup;
  }

  input = read_file(tc.in);
  if (!input) {
    ret_val = 1;
    goto cleanup;
  }

  GoUint8 ok;

  if (tc.fn != NULL) {
    ok = tc.fn(&resp, input, &status);
  } else {
    cfg = read_file(tc.cfg);
    if (!cfg) {
      ret_val = 1;
      goto cleanup;
    }
    ok = tc.fn2(&resp, input, cfg, &status);
  }

  if ((bool)ok != (bool)tc.expected_ok) {
    fprintf(stderr, "expected ok=%d, got ok=%d\n", tc.expected_ok, ok);
    ret_val = 1;
  }

  if (!ok) {
    if (status == NULL) {
      fprintf(stderr, "status is NULL on failure\n");
      ret_val = 1;
      goto cleanup;
    }
    if (status->status != tc.expected_status_code) {
      fprintf(stderr, "expected status code %d, got %d (msg: %s)\n",
              tc.expected_status_code, status->status,
              status->error_msg ? status->error_msg : "<null>");
      ret_val = 1;
    }
    PLGNFreeStatus(status);
    status = NULL;
  }

cleanup:
  if (input) free(input);
  if (cfg) free(cfg);
  if (resp) free(resp);
  if (status) PLGNFreeStatus(status);
  return ret_val;
}

int
main() {
  int ret_val = 0;
  for (int i = 0; i < (int)(sizeof(testCases) / sizeof(TEST_STATUS)); i++) {
    int r = run_status_test(testCases[i]);
    if (r != 0) {
      ret_val = r;
      printf("FAILED: %s\n", testCases[i].in);
    } else {
      printf("OK: %s\n", testCases[i].in);
    }
  }
  return ret_val;
}
