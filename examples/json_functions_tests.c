#include "common.h"
#include <stdbool.h>

#include <cJSON.h>

// GoUint8 is a C bool type
typedef GoUint8(*FN)(char**, char*, PLGNStatus**);

// if return is false, test is not passed
typedef bool(*JSProcess)(cJSON *);

bool
remove_timestamp_field(cJSON *obj) {
  cJSON *inputs = cJSON_GetObjectItemCaseSensitive(obj, "inputs");
  if (inputs == NULL) {
	fprintf(stderr, "the key 'inputs' is not found in the object\n");
	return false;
  }
  cJSON *ts = cJSON_DetachItemFromObjectCaseSensitive(inputs, "timestamp");
  if (ts == NULL) {
	fprintf(stderr, "the key 'timestamp' is not found in the 'inputs' object\n");
	return false;
  }
  bool ok = {true};
  if (cJSON_IsNumber(ts) == 0) {
	fprintf(stderr, "the key 'timestamp' is expected to be a number, but it is not\n");
	ok = false;
  }
  cJSON_Delete(ts);
  return ok;
}

typedef struct _TEST {
  char *in;
  char *out;
  FN fn;
  JSProcess resultPostprocessFn;
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
  },
  {
	.in = "testdata/profile_id_in.json",
	.out = "testdata/profile_id_out.json",
	.fn = &PLGNProfileID
  },
  // timestamp is different on each call, so we can't just compare output for equality
  {
	.in = "testdata/sig_v2_inputs_in.json",
	.out = "testdata/sig_v2_inputs_out.json",
	.fn = &PLGNSigV2Inputs,
	.resultPostprocessFn = remove_timestamp_field
  }
};

bool
json_equal(const char *want, const char *actual,
		   JSProcess resultPostprocessFn) {
  cJSON *wantJson = NULL;
  cJSON *actualJson = NULL;
  wantJson = cJSON_Parse(want);
  actualJson = cJSON_Parse(actual);

  bool ok = {0};
  if (resultPostprocessFn != NULL) {
	ok = resultPostprocessFn(actualJson);
	if (!ok) {
	  goto cleanup;
	}
  }

  ok = 0 != cJSON_Compare(wantJson, actualJson, 1);

 cleanup:
  cJSON_Delete(wantJson);
  cJSON_Delete(actualJson);

  return ok;
}

// return 0 on success or non-0 on error
int
run_test(char *in, char *out, FN fn,
		 JSProcess resultPostprocessFn) {
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

  bool ok = fn(&resp, input, &status);
  if (!ok) {
	consume_status(status, "Error marshaling input");
	ret_val = 1;
	goto cleanup;
  }

  ok = json_equal(want_output, resp, resultPostprocessFn);
  if (!ok) {
	ret_val = 1;
	fprintf(stderr, "result is not equal to expected output\n\ngot:  %s\n\nwant: %s\n\n",
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
	int r = run_test(testCases[i].in, testCases[i].out, testCases[i].fn,
					 testCases[i].resultPostprocessFn);
	if (r != 0) {
	  ret_val = r;
	  printf("FAILED: %s => %s\n", testCases[i].in, testCases[i].out);
	} else {
	  printf("OK: %s => %s\n", testCases[i].in, testCases[i].out);
	}
  }
  return ret_val;
}
