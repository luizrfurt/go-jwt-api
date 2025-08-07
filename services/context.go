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

func CreateDefaultContext(userId uint) error {
	context := models.Context{
		Name:        "My Workspace",
		Description: "Default workspace",
		OwnerId:     userId,
		Active:      true,
	}

	if err := db.DB.Create(&context).Error; err != nil {
		return err
	}

	userContext := models.UserContext{
		UserId:    userId,
		ContextId: context.Id,
		Role:      "owner",
		Selected:  true,
	}

	return db.DB.Create(&userContext).Error
}

func GetUserContexts(userId uint) ([]models.Context, int, string, error) {
	var contexts []models.Context

	err := db.DB.Table("contexts").
		Joins("JOIN user_contexts ON contexts.id = user_contexts.context_id").
		Where("user_contexts.user_id = ? AND contexts.owner_id = ?", userId, userId).
		Find(&contexts).Error

	if err != nil {
		return nil, http.StatusInternalServerError, "Database error", err
	}

	return contexts, 0, "", nil
}

func GetSelectedContext(userId uint) (*models.Context, int, string, error) {
	var userContext models.UserContext

	err := db.DB.Preload("Context").
		Where("user_id = ? AND selected = ?", userId, true).
		First(&userContext).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, "No selected context found", nil
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
		Active:      true,
	}

	if err := db.DB.Create(&context).Error; err != nil {
		return nil, http.StatusInternalServerError, "Failed to create context", err
	}

	userContext := models.UserContext{
		UserId:    userId,
		ContextId: context.Id,
		Role:      "owner",
		Selected:  false,
	}

	if err := db.DB.Create(&userContext).Error; err != nil {
		return nil, http.StatusInternalServerError, "Failed to create user context relation", err
	}

	return &context, 0, "", nil
}

func UpdateContext(userId uint, contextId uint, req validators.UpdateContextRequest) (*models.Context, int, string, error) {
	context, status, message, err := GetContextById(contextId)
	if status != 0 {
		return nil, status, message, err
	}

	if context.OwnerId != userId {
		return nil, http.StatusForbidden, "Access denied to this context", nil
	}

	if !context.Active {
		return nil, http.StatusBadRequest, "Cannot update inactive context", nil
	}

	context.Name = req.Name
	context.Description = req.Description

	if err := db.DB.Save(context).Error; err != nil {
		return nil, http.StatusInternalServerError, "Failed to update context", err
	}

	return context, 0, "", nil
}

func ActivateContext(userId uint, contextId uint) (int, string, error) {
	context, status, message, err := GetContextById(contextId)
	if status != 0 {
		return status, message, err
	}

	if context.OwnerId != userId {
		return http.StatusForbidden, "Access denied to this context", nil
	}

	if context.Active {
		return http.StatusBadRequest, "Context is already active", nil
	}

	context.Active = true
	if err := db.DB.Save(context).Error; err != nil {
		return http.StatusInternalServerError, "Failed to activate context", err
	}

	return 0, "", nil
}

func DeactivateContext(userId uint, contextId uint) (int, string, error) {
	context, status, message, err := GetContextById(contextId)
	if status != 0 {
		return status, message, err
	}

	if context.OwnerId != userId {
		return http.StatusForbidden, "Access denied to this context", nil
	}

	if !context.Active {
		return http.StatusBadRequest, "Context is already inactive", nil
	}

	var activeContextCount int64
	err = db.DB.Model(&models.Context{}).
		Where("owner_id = ? AND active = ?", userId, true).
		Count(&activeContextCount).Error
	if err != nil {
		return http.StatusInternalServerError, "Failed to count active contexts", err
	}

	if activeContextCount <= 1 {
		return http.StatusBadRequest, "Cannot deactivate the only active context", nil
	}

	selectedContext, _, _, _ := GetSelectedContext(userId)
	if selectedContext != nil && selectedContext.Id == contextId {
		err = db.DB.Model(&models.UserContext{}).
			Where("user_id = ? AND context_id = ?", userId, contextId).
			Update("selected", false).Error
		if err != nil {
			return http.StatusInternalServerError, "Failed to deselect context", err
		}

		var userContext models.UserContext
		err = db.DB.Joins("JOIN contexts ON contexts.id = user_contexts.context_id").
			Where("user_contexts.user_id = ? AND contexts.active = ? AND contexts.id != ?", userId, true, contextId).
			First(&userContext).Error
		if err == nil {
			err = db.DB.Model(&userContext).Update("selected", true).Error
			if err != nil {
				return http.StatusInternalServerError, "Failed to select alternative context", err
			}
		}
	}

	context.Active = false
	if err := db.DB.Save(context).Error; err != nil {
		return http.StatusInternalServerError, "Failed to deactivate context", err
	}

	return 0, "", nil
}

func DeleteContext(userId uint, contextId uint) (int, string, error) {
	context, status, message, err := GetContextById(contextId)
	if status != 0 {
		return status, message, err
	}

	if context.OwnerId != userId {
		return http.StatusForbidden, "Access denied to this context", nil
	}

	if context.Active {
		return http.StatusBadRequest, "Cannot delete active context. Deactivate it first", nil
	}

	selectedContext, _, _, _ := GetSelectedContext(userId)
	if selectedContext != nil && selectedContext.Id == contextId {
		err = db.DB.Model(&models.UserContext{}).
			Where("user_id = ? AND context_id = ?", userId, contextId).
			Update("selected", false).Error
		if err != nil {
			return http.StatusInternalServerError, "Failed to deselect context", err
		}

		var userContext models.UserContext
		err = db.DB.Joins("JOIN contexts ON contexts.id = user_contexts.context_id").
			Where("user_contexts.user_id = ? AND contexts.active = ?", userId, true).
			First(&userContext).Error
		if err == nil {
			err = db.DB.Model(&userContext).Update("selected", true).Error
			if err != nil {
				return http.StatusInternalServerError, "Failed to select alternative context", err
			}
		}
	}

	err = db.DB.Where("context_id = ?", contextId).Delete(&models.UserContext{}).Error
	if err != nil {
		return http.StatusInternalServerError, "Failed to remove user associations", err
	}

	err = db.DB.Delete(context).Error
	if err != nil {
		return http.StatusInternalServerError, "Failed to delete context", err
	}

	return 0, "Context deleted successfully", nil
}

func SelectContext(userId uint, contextId uint) (int, string, error) {
	context, status, message, err := GetContextById(contextId)
	if status != 0 {
		return status, message, err
	}

	if !context.Active {
		return http.StatusBadRequest, "Cannot select inactive context", nil
	}

	var userContext models.UserContext
	err = db.DB.Where("user_id = ? AND context_id = ?", userId, contextId).First(&userContext).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusForbidden, "Access denied to this context", nil
		}
		return http.StatusInternalServerError, "Database error", err
	}

	err = db.DB.Model(&models.UserContext{}).
		Where("user_id = ?", userId).
		Update("selected", false).Error
	if err != nil {
		return http.StatusInternalServerError, "Failed to deselect current context", err
	}

	err = db.DB.Model(&userContext).Update("selected", true).Error
	if err != nil {
		return http.StatusInternalServerError, "Failed to select context", err
	}

	return 0, "", nil
}

func HasContextAccess(userId uint, contextId uint) bool {
	var count int64
	db.DB.Model(&models.UserContext{}).
		Joins("JOIN contexts ON contexts.id = user_contexts.context_id").
		Where("user_contexts.user_id = ? AND user_contexts.context_id = ? AND contexts.active = ?", userId, contextId, true).
		Count(&count)

	return count > 0
}
