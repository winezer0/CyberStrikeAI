package audit

import (
	"time"

	"go.uber.org/zap"
)

// StartRetentionLoop periodically purges expired audit rows.
func StartRetentionLoop(s *Service, logger *zap.Logger) {
	if s == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			s.PurgeExpired()
			if logger != nil {
				logger.Debug("audit retention tick completed")
			}
		}
	}()
}
