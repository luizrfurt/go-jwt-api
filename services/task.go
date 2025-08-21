// services/task.go
package services

import (
	"errors"
	"go-jwt-api/db"
	"go-jwt-api/models"
	"go-jwt-api/validators"
	"net/http"

	"gorm.io/gorm"
)

func GetTaskById(taskId uint) (*models.Task, int, string, error) {
	var task models.Task
	err := db.DB.First(&task, taskId).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, "Task not found", nil
		}
		return nil, http.StatusInternalServerError, "Database error", err
	}
	return &task, 0, "", nil
}

func GetUserTasks(userId uint, contextId uint) ([]models.Task, int, string, error) {
	var tasks []models.Task

	err := db.DB.Where("user_id = ? AND context_id = ?", userId, contextId).
		Order("created_at DESC").
		Find(&tasks).Error

	if err != nil {
		return nil, http.StatusInternalServerError, "Database error", err
	}

	return tasks, 0, "", nil
}

func CreateTask(userId uint, contextId uint, req validators.CreateTaskRequest) (*models.Task, int, string, error) {
	status := req.Status
	if status == "" {
		status = "to_do"
	}

	task := models.Task{
		Title:     req.Title,
		Content:   req.Content,
		Status:    status,
		UserId:    userId,
		ContextId: contextId,
	}

	if err := db.DB.Create(&task).Error; err != nil {
		return nil, http.StatusInternalServerError, "Failed to create task", err
	}

	return &task, 0, "", nil
}

func UpdateTask(userId uint, contextId uint, taskId uint, req validators.UpdateTaskRequest) (*models.Task, int, string, error) {
	task, status, message, err := GetTaskById(taskId)
	if status != 0 {
		return nil, status, message, err
	}

	if task.UserId != userId || task.ContextId != contextId {
		return nil, http.StatusForbidden, "Access denied to this task", nil
	}

	task.Title = req.Title
	task.Content = req.Content
	task.Status = req.Status

	if err := db.DB.Save(task).Error; err != nil {
		return nil, http.StatusInternalServerError, "Failed to update task", err
	}

	return task, 0, "", nil
}

func DeleteTask(userId uint, contextId uint, taskId uint) (int, string, error) {
	task, status, message, err := GetTaskById(taskId)
	if status != 0 {
		return status, message, err
	}

	if task.UserId != userId || task.ContextId != contextId {
		return http.StatusForbidden, "Access denied to this task", nil
	}

	err = db.DB.Delete(task).Error
	if err != nil {
		return http.StatusInternalServerError, "Failed to delete task", err
	}

	return 0, "Task deleted successfully", nil
}
