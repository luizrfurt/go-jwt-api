// validators/validator.go
package validators

import (
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
}

func ValidateStruct(data interface{}) map[string]string {
	err := validate.Struct(data)
	if err == nil {
		return nil
	}

	errors := make(map[string]string)
	for _, err := range err.(validator.ValidationErrors) {
		jsonFieldName := getJSONFieldName(data, err.Field())
		errors[err.Field()] = generateErrorMessage(err, jsonFieldName)
	}
	return errors
}

func getJSONFieldName(structInstance interface{}, fieldName string) string {
	structType := reflect.TypeOf(structInstance)

	if structType.Kind() == reflect.Ptr {
		structType = structType.Elem()
	}

	field, found := structType.FieldByName(fieldName)
	if !found {
		return strings.ToLower(fieldName)
	}

	jsonTag := field.Tag.Get("json")
	if jsonTag == "" {
		return strings.ToLower(fieldName)
	}

	jsonName := strings.Split(jsonTag, ",")[0]
	if jsonName == "" || jsonName == "-" {
		return strings.ToLower(fieldName)
	}

	return jsonName
}

func generateErrorMessage(fe validator.FieldError, jsonFieldName string) string {
	switch fe.Tag() {
	case "required":
		return "Field '" + jsonFieldName + "' is required"
	case "min":
		return "Field '" + jsonFieldName + "' must be at least " + fe.Param() + " characters"
	case "max":
		return "Field '" + jsonFieldName + "' must be at most " + fe.Param() + " characters"
	case "len":
		return "Field '" + jsonFieldName + "' must be exactly " + fe.Param() + " characters"
	case "eq":
		return "Field '" + jsonFieldName + "' must be equal to " + fe.Param()
	case "eqfield":
		if jsonFieldName == "confirm_new_password" {
			return "Passwords do not match"
		}
		return "Field '" + jsonFieldName + "' must be equal to field '" + strings.ToLower(fe.Param()) + "'"
	case "ne":
		return "Field '" + jsonFieldName + "' must not be equal to " + fe.Param()
	case "gte":
		return "Field '" + jsonFieldName + "' must be greater than or equal to " + fe.Param()
	case "gt":
		return "Field '" + jsonFieldName + "' must be greater than " + fe.Param()
	case "lte":
		return "Field '" + jsonFieldName + "' must be less than or equal to " + fe.Param()
	case "lt":
		return "Field '" + jsonFieldName + "' must be less than " + fe.Param()
	case "email":
		return "Field '" + jsonFieldName + "' must be a valid email address"
	case "url":
		return "Field '" + jsonFieldName + "' must be a valid URL"
	case "uuid":
		return "Field '" + jsonFieldName + "' must be a valid UUID"
	case "numeric":
		return "Field '" + jsonFieldName + "' must be a numeric value"
	case "alpha":
		return "Field '" + jsonFieldName + "' must contain only letters"
	case "alphanum":
		return "Field '" + jsonFieldName + "' must contain only letters and numbers"
	case "oneof":
		return "Field '" + jsonFieldName + "' must be one of: " + fe.Param()
	case "contains":
		return "Field '" + jsonFieldName + "' must contain " + fe.Param()
	case "startswith":
		return "Field '" + jsonFieldName + "' must start with " + fe.Param()
	case "endswith":
		return "Field '" + jsonFieldName + "' must end with " + fe.Param()
	default:
		return "Field '" + jsonFieldName + "' is invalid"
	}
}
