// validators/audit.go
package validators

type AuditLogFilters struct {
	UserId    *uint  `form:"user_id"`
	ContextId *uint  `form:"context_id"`
	Action    string `form:"action"`
	StartDate string `form:"start_date" validate:"omitempty,datetime=2006-01-02"`
	EndDate   string `form:"end_date" validate:"omitempty,datetime=2006-01-02"`
	Limit     int    `form:"limit" validate:"min=1,max=100"`
	Offset    int    `form:"offset" validate:"min=0"`
}
