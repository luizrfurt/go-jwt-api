// validators/context.go
package validators

type CreateContextRequest struct {
	Name        string `json:"name" validate:"required,min=3,max=50"`
	Description string `json:"description" validate:"required,min=3,max=200"`
}

type UpdateContextRequest struct {
	Name        string `json:"name" validate:"required,min=3,max=50"`
	Description string `json:"description" validate:"required,min=3,max=200"`
}
