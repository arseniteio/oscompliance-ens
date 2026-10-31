package source

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Wazuh indexes top-level scalars of a fact as strings; Decode converts them back to the field types.
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
		case reflect.Float32, reflect.Float64:
			n, err := strconv.ParseFloat(s, 64)
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
