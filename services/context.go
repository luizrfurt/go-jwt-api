// services/context.go
package services

import (
	"errors"
	"go-jwt-api/db"
	"go-jwt-api/models"
	"go-jwt-api/validators"
	"net/http"

	"gorm.io/gorm"
)

func CreateDefaultContext(userId uint) error {
	context := models.Context{
		Name:        "My Workspace",
		Description: "Default workspace",
		OwnerId:     userId,
	}

	if err := db.DB.Create(&context).Error; err != nil {
		return err
	}

	userContext := models.UserContext{
		UserId:    userId,
		ContextId: context.Id,
		Role:      "owner",
		IsActive:  true,
	}

	return db.DB.Create(&userContext).Error
}

func GetUserContexts(userId uint) ([]models.Context, int, string, error) {
	var contexts []models.Context

	err := db.DB.Table("contexts").
		Joins("JOIN user_contexts ON contexts.id = user_contexts.context_id").
		Where("user_contexts.user_id = ?", userId).
		Find(&contexts).Error

	if err != nil {
		return nil, http.StatusInternalServerError, "Database error", err
	}

	return contexts, 0, "", nil
}

func GetActiveContext(userId uint) (*models.Context, int, string, error) {
	var userContext models.UserContext

	err := db.DB.Preload("Context").
		Where("user_id = ? AND is_active = ?", userId, true).
		First(&userContext).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, "No active context found", nil
		}
		return nil, http.StatusInternalServerError, "Database error", err
	}

	return &userContext.Context, 0, "", nil
}

func CreateContext(userId uint, req validators.CreateContextRequest) (*models.Context, int, string, error) {
	context := models.Context{
		Name:        req.Name,
		Description: req.Description,
		OwnerId:     userId,
	}

	if err := db.DB.Create(&context).Error; err != nil {
		return nil, http.StatusInternalServerError, "Failed to create context", err
	}

	userContext := models.UserContext{
		UserId:    userId,
		ContextId: context.Id,
		Role:      "owner",
		IsActive:  false,
	}

	if err := db.DB.Create(&userContext).Error; err != nil {
		return nil, http.StatusInternalServerError, "Failed to create user context relation", err
	}

	return &context, 0, "", nil
}

func SelectContext(userId uint, contextId uint) (int, string, error) {
	var userContext models.UserContext
	err := db.DB.Where("user_id = ? AND context_id = ?", userId, contextId).First(&userContext).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusForbidden, "Access denied to this context", nil
		}
		return http.StatusInternalServerError, "Database error", err
	}

	err = db.DB.Model(&models.UserContext{}).
		Where("user_id = ?", userId).
		Update("is_active", false).Error
	if err != nil {
		return http.StatusInternalServerError, "Failed to deactivate current context", err
	}

	err = db.DB.Model(&userContext).Update("is_active", true).Error
	if err != nil {
		return http.StatusInternalServerError, "Failed to activate context", err
	}

	return 0, "", nil
}

func HasContextAccess(userId uint, contextId uint) bool {
	var count int64
	db.DB.Model(&models.UserContext{}).
		Where("user_id = ? AND context_id = ?", userId, contextId).
		Count(&count)

	return count > 0
}

func GetContextById(contextId uint) (*models.Context, int, string, error) {
	var context models.Context
	err := db.DB.First(&context, contextId).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, "Context not found", nil
		}
		return nil, http.StatusInternalServerError, "Database error", err
	}
	return &context, 0, "", nil
}
