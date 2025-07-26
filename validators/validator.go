// validators/validator.go
package validators

import (
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
	switch fe.Tag() {
	case "required":
		return fe.Field() + " is required"
	case "min":
		return fe.Field() + " must be at least " + fe.Param() + " characters"
	case "max":
		return fe.Field() + " must be at most " + fe.Param() + " characters"
	case "len":
		return fe.Field() + " must be exactly " + fe.Param() + " characters"
	case "eq":
		return fe.Field() + " must be equal to " + fe.Param()
	case "ne":
		return fe.Field() + " must not be equal to " + fe.Param()
	case "gte":
		return fe.Field() + " must be greater than or equal to " + fe.Param()
	case "gt":
		return fe.Field() + " must be greater than " + fe.Param()
	case "lte":
		return fe.Field() + " must be less than or equal to " + fe.Param()
	case "lt":
		return fe.Field() + " must be less than " + fe.Param()
	case "email":
		return fe.Field() + " must be a valid email address"
	case "url":
		return fe.Field() + " must be a valid URL"
	case "uuid":
		return fe.Field() + " must be a valid UUID"
	case "numeric":
		return fe.Field() + " must be a numeric value"
	case "alpha":
		return fe.Field() + " must contain only letters"
	case "alphanum":
		return fe.Field() + " must contain only letters and numbers"
	case "oneof":
		return fe.Field() + " must be one of: " + fe.Param()
	case "contains":
		return fe.Field() + " must contain " + fe.Param()
	case "startswith":
		return fe.Field() + " must start with " + fe.Param()
	case "endswith":
		return fe.Field() + " must end with " + fe.Param()
	default:
		return fe.Field() + " is invalid"
	}
}
