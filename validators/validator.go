// validators/validator.go
package validators

import (
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
		errors[err.Field()] = generateErrorMessage(err)
	}
	return errors
}

func generateErrorMessage(fe validator.FieldError) string {
	field := strings.ToLower(fe.Field())
	switch fe.Tag() {
	case "required":
		return "Field '" + field + "' is required"
	case "min":
		return "Field '" + field + "' must be at least " + fe.Param() + " characters"
	case "max":
		return "Field '" + field + "' must be at most " + fe.Param() + " characters"
	case "len":
		return "Field '" + field + "' must be exactly " + fe.Param() + " characters"
	case "eq":
		return "Field '" + field + "' must be equal to " + fe.Param()
	case "ne":
		return "Field '" + field + "' must not be equal to " + fe.Param()
	case "gte":
		return "Field '" + field + "' must be greater than or equal to " + fe.Param()
	case "gt":
		return "Field '" + field + "' must be greater than " + fe.Param()
	case "lte":
		return "Field '" + field + "' must be less than or equal to " + fe.Param()
	case "lt":
		return "Field '" + field + "' must be less than " + fe.Param()
	case "email":
		return "Field '" + field + "' must be a valid email address"
	case "url":
		return "Field '" + field + "' must be a valid URL"
	case "uuid":
		return "Field '" + field + "' must be a valid UUID"
	case "numeric":
		return "Field '" + field + "' must be a numeric value"
	case "alpha":
		return "Field '" + field + "' must contain only letters"
	case "alphanum":
		return "Field '" + field + "' must contain only letters and numbers"
	case "oneof":
		return "Field '" + field + "' must be one of: " + fe.Param()
	case "contains":
		return "Field '" + field + "' must contain " + fe.Param()
	case "startswith":
		return "Field '" + field + "' must start with " + fe.Param()
	case "endswith":
		return "Field '" + field + "' must end with " + fe.Param()
	default:
		return "Field '" + field + "' is invalid"
	}
}

