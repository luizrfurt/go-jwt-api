// handlers/task.go
package handlers

import (
	"go-jwt-api/middlewares"
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"go-jwt-api/validators"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

func GetMyTasks(c *gin.Context) {
	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "task_list_view_failed", nil, nil, map[string]interface{}{
			"reason": "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	contextId, exists := c.Get("ctx")
	if !exists {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "task_list_view_failed", &userIdStr, nil, map[string]interface{}{
			"user_id": userId.(uint),
			"reason":  "context_not_in_request",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "Context not found"}, []string{})
		return
	}

	tasks, status, message, _ := services.GetUserTasks(userId.(uint), contextId.(uint))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "task_list_view_failed", &userIdStr, nil, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": contextId.(uint),
			"reason":     "service_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	type TaskResponse struct {
		Id        uint      `json:"id"`
		Title     string    `json:"title"`
		Content   string    `json:"content"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	response := make([]TaskResponse, 0)

	for _, task := range tasks {
		response = append(response, TaskResponse{
			Id:        task.Id,
			Title:     task.Title,
			Content:   task.Content,
			Status:    task.Status,
			CreatedAt: task.CreatedAt,
			UpdatedAt: task.UpdatedAt,
		})
	}

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	middlewares.SetAuditData(c, "task_list_view_success", &userIdStr, nil, map[string]interface{}{
		"user_id":     userId.(uint),
		"context_id":  contextId.(uint),
		"tasks_count": len(response),
	})

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Tasks retrieved successfully"}, response)
}

func CreateTask(c *gin.Context) {
	var req validators.CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "task_create_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id": userId.(uint),
				"reason":  "invalid_json",
				"error":   err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid create task request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "task_create_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":           userId.(uint),
				"title":             req.Title,
				"status":            req.Status,
				"reason":            "validation_failed",
				"validation_errors": validationErrors,
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "task_create_failed", nil, nil, map[string]interface{}{
			"reason": "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	contextId, exists := c.Get("ctx")
	if !exists {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "task_create_failed", &userIdStr, nil, map[string]interface{}{
			"user_id": userId.(uint),
			"reason":  "context_not_in_request",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "Context not found"}, []string{})
		return
	}

	task, status, message, _ := services.CreateTask(userId.(uint), contextId.(uint), req)
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "task_create_failed", &userIdStr, nil, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": contextId.(uint),
			"title":      req.Title,
			"status":     req.Status,
			"reason":     "service_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	type TaskResponse struct {
		Id        uint      `json:"id"`
		Title     string    `json:"title"`
		Content   string    `json:"content"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	createdResp := TaskResponse{
		Id:        task.Id,
		Title:     task.Title,
		Content:   task.Content,
		Status:    task.Status,
		CreatedAt: task.CreatedAt,
		UpdatedAt: task.UpdatedAt,
	}

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	taskIdStr := strconv.FormatUint(uint64(task.Id), 10)
	middlewares.SetAuditData(c, "task_create_success", &userIdStr, nil, map[string]interface{}{
		"user_id":    userId.(uint),
		"context_id": contextId.(uint),
		"task_id":    task.Id,
		"title":      task.Title,
		"status":     task.Status,
	})

	c.Set("resource_id", taskIdStr)

	utils.SendJSON(
		c,
		http.StatusCreated,
		gin.H{"message": "Task created successfully"},
		[]TaskResponse{createdResp},
	)
}

func UpdateTask(c *gin.Context) {
	taskIdStr := c.Param("id")
	taskId, err := strconv.ParseUint(taskIdStr, 10, 32)
	if err != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "task_update_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id": userId.(uint),
				"task_id": taskIdStr,
				"reason":  "invalid_task_id",
				"error":   err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid task ID"}, []string{})
		return
	}

	var req validators.UpdateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "task_update_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id": userId.(uint),
				"task_id": uint(taskId),
				"reason":  "invalid_json",
				"error":   err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid update task request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "task_update_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":           userId.(uint),
				"task_id":           uint(taskId),
				"title":             req.Title,
				"status":            req.Status,
				"reason":            "validation_failed",
				"validation_errors": validationErrors,
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "task_update_failed", nil, nil, map[string]interface{}{
			"task_id": uint(taskId),
			"reason":  "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	contextId, exists := c.Get("ctx")
	if !exists {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "task_update_failed", &userIdStr, nil, map[string]interface{}{
			"user_id": userId.(uint),
			"task_id": uint(taskId),
			"reason":  "context_not_in_request",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "Context not found"}, []string{})
		return
	}

	oldTask, _, _, _ := services.GetTaskById(uint(taskId))
	var oldValues interface{}
	if oldTask != nil {
		oldValues = map[string]interface{}{
			"title":   oldTask.Title,
			"content": oldTask.Content,
			"status":  oldTask.Status,
		}
	}

	task, status, message, _ := services.UpdateTask(userId.(uint), contextId.(uint), uint(taskId), req)
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "task_update_failed", &userIdStr, oldValues, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": contextId.(uint),
			"task_id":    uint(taskId),
			"title":      req.Title,
			"status":     req.Status,
			"reason":     "service_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	type TaskResponse struct {
		Id        uint      `json:"id"`
		Title     string    `json:"title"`
		Content   string    `json:"content"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	updatedResp := TaskResponse{
		Id:        task.Id,
		Title:     task.Title,
		Content:   task.Content,
		Status:    task.Status,
		CreatedAt: task.CreatedAt,
		UpdatedAt: task.UpdatedAt,
	}

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	taskIdStrConverted := strconv.FormatUint(uint64(task.Id), 10)
	newValues := map[string]interface{}{
		"title":   req.Title,
		"content": req.Content,
		"status":  req.Status,
	}
	middlewares.SetAuditData(c, "task_update_success", &userIdStr, oldValues, newValues)

	c.Set("resource_id", taskIdStrConverted)

	utils.SendJSON(
		c,
		http.StatusOK,
		gin.H{"message": "Task updated successfully"},
		[]TaskResponse{updatedResp},
	)
}

func DeleteTask(c *gin.Context) {
	taskIdStr := c.Param("id")
	taskId, err := strconv.ParseUint(taskIdStr, 10, 32)
	if err != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "task_delete_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id": userId.(uint),
				"task_id": taskIdStr,
				"reason":  "invalid_task_id",
				"error":   err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid task ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "task_delete_failed", nil, nil, map[string]interface{}{
			"task_id": uint(taskId),
			"reason":  "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	contextId, exists := c.Get("ctx")
	if !exists {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "task_delete_failed", &userIdStr, nil, map[string]interface{}{
			"user_id": userId.(uint),
			"task_id": uint(taskId),
			"reason":  "context_not_in_request",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "Context not found"}, []string{})
		return
	}

	taskToDelete, _, _, _ := services.GetTaskById(uint(taskId))
	var oldValues interface{}
	if taskToDelete != nil {
		oldValues = map[string]interface{}{
			"title":   taskToDelete.Title,
			"content": taskToDelete.Content,
			"status":  taskToDelete.Status,
		}
	}

	status, message, _ := services.DeleteTask(userId.(uint), contextId.(uint), uint(taskId))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "task_delete_failed", &userIdStr, oldValues, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": contextId.(uint),
			"task_id":    uint(taskId),
			"reason":     "service_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	taskIdStrConverted := strconv.FormatUint(uint64(taskId), 10)
	middlewares.SetAuditData(c, "task_delete_success", &userIdStr, oldValues, map[string]interface{}{
		"user_id":    userId.(uint),
		"context_id": contextId.(uint),
		"task_id":    uint(taskId),
	})

	c.Set("resource_id", taskIdStrConverted)

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Task deleted successfully"}, []string{})
}
