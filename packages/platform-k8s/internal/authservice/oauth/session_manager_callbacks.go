package oauth

import (
	"context"
	"time"
)

// CodeCallbackRecordedEvent confirms that one code-flow callback payload was persisted.
type CodeCallbackRecordedEvent struct {
	SessionID  string
	RecordedAt time.Time
}

func (m *SessionManager) SetCodeCallbackRecordedHook(hook func(context.Context, string)) {
	if m != nil {
		m.codeCallbackRecorded = hook
	}
}
