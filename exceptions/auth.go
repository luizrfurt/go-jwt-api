// exceptions/auth.go
package exceptions

import (
	"errors"
	"go-jwt-api/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}

type ErrorMapping struct {
	StatusCode int
	Message    string
}

var authErrorMap = map[error]ErrorMapping{
	services.ErrUsernameExists: {
		StatusCode: http.StatusBadRequest,
		Message:    "Username already exists",
	},
	services.ErrEmailExists: {
		StatusCode: http.StatusBadRequest,
		Message:    "Email already exists",
	},
	services.ErrUserNotFound: {
		StatusCode: http.StatusUnauthorized,
		Message:    "User not found",
	},
	services.ErrIncorrectPassword: {
		StatusCode: http.StatusUnauthorized,
		Message:    "Incorrect password",
	},
	services.ErrInvalidToken: {
		StatusCode: http.StatusUnauthorized,
		Message:    "Invalid token",
	},
	services.ErrInvalidTokenType: {
		StatusCode: http.StatusUnauthorized,
		Message:    "Invalid token type",
	},
	services.ErrHashPassword: {
		StatusCode: http.StatusInternalServerError,
		Message:    "Could not hash password",
	},
	services.ErrCreateUser: {
		StatusCode: http.StatusInternalServerError,
		Message:    "Failed to create user",
	},
	services.ErrGenerateTokens: {
		StatusCode: http.StatusInternalServerError,
		Message:    "Could not generate tokens",
	},
	services.ErrDatabaseError: {
		StatusCode: http.StatusInternalServerError,
		Message:    "Database error",
	},
}

func HandleAuthError(c *gin.Context, err error) {
	for serviceErr, mapping := range authErrorMap {
		if errors.Is(err, serviceErr) {
			c.JSON(mapping.StatusCode, ErrorResponse{Error: mapping.Message})
			return
		}
	}

	c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Internal server error"})
}

func HandleAuthErrorWithCustomStatus(c *gin.Context, err error, customMappings map[error]ErrorMapping) {
	for serviceErr, mapping := range customMappings {
		if errors.Is(err, serviceErr) {
			c.JSON(mapping.StatusCode, ErrorResponse{Error: mapping.Message})
			return
		}
	}

	HandleAuthError(c, err)
}

func BadRequestError(c *gin.Context, message string) {
	c.JSON(http.StatusBadRequest, ErrorResponse{Error: message})
}

func InternalServerError(c *gin.Context, message string) {
	c.JSON(http.StatusInternalServerError, ErrorResponse{Error: message})
}

func UnauthorizedError(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, ErrorResponse{Error: message})
}

func NotFoundError(c *gin.Context, message string) {
	c.JSON(http.StatusNotFound, ErrorResponse{Error: message})
}

func ValidationError(c *gin.Context, validationErrors interface{}) {
	c.JSON(http.StatusBadRequest, gin.H{"validation_errors": validationErrors})
}
