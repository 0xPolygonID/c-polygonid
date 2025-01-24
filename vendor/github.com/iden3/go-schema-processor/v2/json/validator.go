package json

import (
	"bytes"
	"encoding/json"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

// Validator validate json data
type Validator struct {
}

// ValidateData validate JSON data by JSON Schema
func (v Validator) ValidateData(data, schema []byte) error {

	compiler := jsonschema.NewCompiler()

	err := compiler.AddResource("temp.json", bytes.NewReader(schema))
	if err != nil {
		return err
	}

	var c map[string]interface{}
	err = json.Unmarshal(data, &c)
	if err != nil {
		return err
	}

	sh, err := compiler.Compile("temp.json")
	if err != nil {
		return err
	}
	return sh.Validate(c)
}
