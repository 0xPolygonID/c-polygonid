package verifiable

import (
	"strings"

	"github.com/pkg/errors"
)

type jsonObj = map[string]any

func jsonObjGetString(o jsonObj, path string) (string, error) {
	v, err := jsonObjGet(o, path)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", errors.Errorf("value is not a string: %s", path)
	}
	return s, nil
}

func jsonObjGet(o jsonObj, path string) (interface{}, error) {
	parts := strings.Split(path, ".")
	var v interface{} = o
	for _, p := range parts {
		var err error
		v, err = jsonObjGetField(v, p)
		if err != nil {
			return nil, err
		}
	}
	return v, nil
}

func jsonObjGetField(v interface{}, p string) (interface{}, error) {
	m, ok := v.(jsonObj)
	if !ok {
		return nil, errors.Errorf("invalid type for path %s", p)
	}
	v, ok = m[p]
	if !ok {
		return nil, errors.Errorf("field %s not found", p)
	}
	return v, nil
}
