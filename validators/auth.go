// validators/auth.go
package validators

type SignUpRequest struct {
	Name     string `json:"name" validate:"required,min=3,max=50"`
	Username string `json:"username" validate:"required,min=3,max=20"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

type SignInRequest struct {
	Username string `json:"username" validate:"required,min=3,max=20"`
	Password string `json:"password" validate:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	NewPassword        string `json:"new_password" validate:"required,min=6"`
	ConfirmNewPassword string `json:"confirm_new_password" validate:"required,eqfield=NewPassword"`
}

type UpdateMeRequest struct {
	Name        string  `json:"name" validate:"required,min=3,max=50"`
	Username    string  `json:"username" validate:"required,min=3,max=20"`
	Email       string  `json:"email" validate:"required,email"`
	NewPassword *string `json:"new_password,omitempty" validate:"omitempty,min=6"`
}
