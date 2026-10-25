package source

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Decode fills v, a pointer to a fact struct, from the data object of a Wazuh
// alert. Wazuh indexes top-level scalars as strings ("1000", "true"), so each
// one is converted back to the type of the struct field with the same JSON
// name. Arrays and objects keep their JSON types and are left as they are.
func Decode(data map[string]any, v any) error {

	kinds := fieldKinds(reflect.TypeOf(v).Elem())

	converted := make(map[string]any, len(data))

	for name, value := range data {

		s, isString := value.(string)
		if !isString {
			converted[name] = value
			continue
		}

		switch kinds[name] {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return fmt.Errorf("decode %s: %w", name, err)
			}
			converted[name] = n
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return fmt.Errorf("decode %s: %w", name, err)
			}
			converted[name] = n
		case reflect.Bool:
			b, err := strconv.ParseBool(s)
			if err != nil {
				return fmt.Errorf("decode %s: %w", name, err)
			}
			converted[name] = b
		default:
			converted[name] = s
		}
	}

	raw, err := json.Marshal(converted)

	if err != nil {
		return err
	}

	return json.Unmarshal(raw, v)
}

// fieldKinds maps each JSON field name of struct type t to its kind, following
// embedded structs (the fact envelope) and pointers (optional fields).
func fieldKinds(t reflect.Type) map[string]reflect.Kind {

	kinds := map[string]reflect.Kind{}

	for i := range t.NumField() {
		f := t.Field(i)

		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			for name, kind := range fieldKinds(f.Type) {
				kinds[name] = kind
			}
			continue
		}

		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}

		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		kinds[name] = ft.Kind()
	}

	return kinds
}
