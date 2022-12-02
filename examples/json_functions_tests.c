#include "common.h"
#include <stdbool.h>

// GoUint8 is a C bool type
typedef GoUint8(*FN)(char**, char*, PLGNStatus**);

typedef struct _TEST {
  char *in;
  char *out;
  FN fn;
} TEST;

TEST testCases[] = {
  {
	.in = "testdata/create_claim_in.json",
	.out = "testdata/create_claim_out.json",
	.fn = &PLGNCreateClaim
  },
  {
	.in = "testdata/create_claim_all_fields_1_in.json",
	.out = "testdata/create_claim_all_fields_1_out.json",
	.fn = &PLGNCreateClaim
  },
  {
	.in = "testdata/create_claim_all_fields_2_in.json",
	.out = "testdata/create_claim_all_fields_2_out.json",
	.fn = &PLGNCreateClaim
  },
  {
	.in = "testdata/auth_v2_inputs_in.json",
	.out = "testdata/auth_v2_inputs_out.json",
	.fn = &PLGNAuthV2InputsMarshal
  },
  {
	.in = "testdata/calculate_genesis_id_in.json",
	.out = "testdata/calculate_genesis_id_out.json",
	.fn = &PLGNCalculateGenesisID
  },
  {
	.in = "testdata/id_to_int_in.json",
	.out = "testdata/id_to_int_out.json",
	.fn = &PLGNIDToInt
  },
  {
	.in = "testdata/proof_from_smart_contract_in.json",
	.out = "testdata/proof_from_smart_contract_out.json",
	.fn = &PLGNProofFromSmartContract
  }
};

// return 0 on success or non-0 on error
int
run_test(char *in, char *out, FN fn) {
  int ret_val = 0;
  char *resp = NULL;
  PLGNStatus *status = NULL;

  char *input = read_file(in);
  if (!input) {
	ret_val = 1;
	goto cleanup;
  }
  char *want_output = read_file(out);
  if (!want_output) {
	ret_val = 1;
	goto cleanup;
  }
  // remove trailing newline
  want_output[strcspn(want_output, "\n")] = 0;

  bool ok = fn(&resp, input, &status);
  if (!ok) {
	consume_status(status, "Error marshaling input");
	ret_val = 1;
	goto cleanup;
  }

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

int
main() {
  int ret_val = 0;
  for(int i = 0; i < sizeof(testCases)/sizeof(TEST); i++) {
	int r = run_test(testCases[i].in, testCases[i].out, testCases[i].fn);
	if (r != 0) {
	  ret_val = r;
	  printf("FAILED: %s => %s\n", testCases[i].in, testCases[i].out);
	} else {
	  printf("OK: %s => %s\n", testCases[i].in, testCases[i].out);
	}
  }
  return ret_val;
}
