// validators/task.go
package validators

type CreateTaskRequest struct {
	Title   string `json:"title" validate:"required,min=3,max=100"`
	Content string `json:"content" validate:"required,min=3,max=1000"`
	Status  string `json:"status,omitempty" validate:"omitempty,oneof=to_do in_progress done"`
}

type UpdateTaskRequest struct {
	Title   string `json:"title" validate:"required,min=3,max=100"`
	Content string `json:"content" validate:"required,min=3,max=1000"`
	Status  string `json:"status" validate:"required,oneof=to_do in_progress done"`
}
