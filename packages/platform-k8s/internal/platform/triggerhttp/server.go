package triggerhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"code-code.internal/platform-k8s/internal/platform/httpauth"
)

const (
	actionPathPrefix = "/internal/actions/"
	defaultMaxBody   = int64(64 << 10)
)

type ActionFunc func(context.Context, Request) (any, error)

type Request struct {
	Action string
	Body   []byte
}

func (r Request) DecodeJSON(target any) error {
	if len(r.Body) == 0 {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(r.Body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode trigger body: %w", err)
	}
	return nil
}

type Config struct {
	Actions   map[string]ActionFunc
	Logger    *slog.Logger
	MaxBody   int64
	AuthToken string
}

type Server struct {
	actions   map[string]ActionFunc
	logger    *slog.Logger
	maxBody   int64
	authToken string
	mux       *http.ServeMux
}

func NewServer(config Config) (*Server, error) {
	if len(config.Actions) == 0 {
		return nil, fmt.Errorf("triggerhttp: actions are empty")
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	maxBody := config.MaxBody
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	actions := map[string]ActionFunc{}
	for name, action := range config.Actions {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("triggerhttp: action name is empty")
		}
		if strings.Contains(name, "/") {
			return nil, fmt.Errorf("triggerhttp: action %q must not contain slash", name)
		}
		if action == nil {
			return nil, fmt.Errorf("triggerhttp: action %q is nil", name)
		}
		if _, exists := actions[name]; exists {
			return nil, fmt.Errorf("triggerhttp: duplicate action %q", name)
		}
		actions[name] = action
	}
	server := &Server{
		actions:   actions,
		logger:    logger,
		maxBody:   maxBody,
		authToken: strings.TrimSpace(config.AuthToken),
		mux:       http.NewServeMux(),
	}
	server.mux.HandleFunc("/readyz", server.handleReady)
	server.mux.HandleFunc(actionPathPrefix, server.handleAction)
	return server, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	actionName := strings.TrimPrefix(r.URL.Path, actionPathPrefix)
	if actionName == "" || strings.Contains(actionName, "/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "action not found"})
		return
	}
	action, ok := s.actions[actionName]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "action not found"})
		return
	}
	if s.authToken == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "action not found"})
		return
	}
	if !httpauth.HasBearerAuthorization(r.Header.Get("Authorization"), s.authToken) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.logger.Warn("reject unauthorized internal action request", "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	result, err := action(r.Context(), Request{Action: actionName, Body: body})
	if err != nil {
		s.logger.Error("trigger action failed", "action", actionName, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"action": actionName,
		"status": "ok",
		"result": result,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
