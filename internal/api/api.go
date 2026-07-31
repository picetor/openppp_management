package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/openppp2/openppp2-management/internal/config"
	"github.com/openppp2/openppp2-management/internal/model"
	"github.com/openppp2/openppp2-management/internal/security"
	"github.com/openppp2/openppp2-management/internal/webui"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Server struct {
	db  *gorm.DB
	cfg config.Config
}

type contextKey string

const userContextKey contextKey = "user"
const communicationKeySetting = "node_communication_key"
const publicURLSetting = "public_url"

func New(db *gorm.DB, cfg config.Config) http.Handler {
	server := &Server{db: db, cfg: cfg}
	if _, err := server.communicationKey(); err != nil {
		panic(err)
	}
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Logger)
	router.Use(middleware.Compress(5))
	router.Use(server.securityHeaders)

	router.Get("/healthz", server.health)
	router.Get("/sub/v1/{token}", server.subscription)
	router.Get("/sub/v1/{token}/nodes/{nodeKey}/config", server.subscriptionNodeConfig)
	router.Get("/sub/v1/{token}/scripts/install.ps1", server.subscriptionInstallPowerShell)
	router.Get("/sub/v1/{token}/scripts/install.sh", server.subscriptionInstallShell)

	router.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/login", server.login)
		r.With(server.authenticated).Post("/auth/logout", server.logout)
		r.With(server.authenticated).Get("/me", server.me)

		r.Group(func(r chi.Router) {
			r.Use(server.authenticated)
			r.Get("/dashboard", server.dashboard)
			r.Get("/users", server.users)
			r.Post("/users", server.adminOnly(server.createUser))
			r.Patch("/users/{userID}", server.adminOnly(server.updateUser))
			r.Put("/users/{userID}/permission-groups", server.adminOnly(server.updateUserPermissionGroups))
			r.Delete("/users/{userID}", server.adminOnly(server.deleteUser))
			r.Get("/settings/communication", server.adminOnly(server.communicationSettings))
			r.Put("/settings/communication", server.adminOnly(server.updateCommunicationSettings))
			r.Get("/settings/general", server.adminOnly(server.generalSettings))
			r.Put("/settings/general", server.adminOnly(server.updateGeneralSettings))
			r.Get("/permission-groups", server.adminOnly(server.permissionGroups))
			r.Post("/permission-groups", server.adminOnly(server.createPermissionGroup))
			r.Patch("/permission-groups/{groupID}", server.adminOnly(server.updatePermissionGroup))
			r.Delete("/permission-groups/{groupID}", server.adminOnly(server.deletePermissionGroup))
			r.Get("/devices", server.devices)
			r.Post("/devices", server.createDevice)
			r.Post("/devices/batch-ban", server.batchBanDevices)
			r.Post("/devices/batch-unban", server.batchUnbanDevices)
			r.Patch("/devices/{deviceID}", server.updateDevice)
			r.Delete("/devices/{deviceID}", server.deleteDevice)
			r.Put("/devices/{deviceID}/nodes", server.assignDeviceNodes)
			r.Post("/devices/{deviceID}/tokens", server.createSubscriptionToken)
			r.Post("/devices/{deviceID}/ban", server.banDevice)
			r.Post("/devices/{deviceID}/unban", server.unbanDevice)
			r.Get("/device-bans", server.deviceBans)
			r.Get("/nodes", server.nodes)
			r.Get("/available-nodes", server.availableNodes)
			r.Post("/nodes", server.adminOnly(server.createNode))
			r.Patch("/nodes/{nodeID}", server.adminOnly(server.updateNode))
			r.Delete("/nodes/{nodeID}", server.adminOnly(server.deleteNode))
			r.Get("/nodes/{nodeID}/rules", server.nodeRules)
			r.Post("/nodes/{nodeID}/rules", server.adminOnly(server.createNodeRule))
			r.Delete("/nodes/{nodeID}/rules/{ruleID}", server.adminOnly(server.deleteNodeRule))
			r.Get("/online", server.online)
		})

		r.Route("/node", func(r chi.Router) {
			r.Use(server.nodeAuthenticated)
			r.Get("/policy", server.nodePolicy)
			r.Post("/heartbeat", server.nodeHeartbeat)
			r.Post("/sessions", server.nodeSessions)
		})
	})

	static, err := fs.Sub(webui.Files, "dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(static))
	router.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if _, err := fs.Stat(static, path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		index, err := fs.ReadFile(static, "index.html")
		if err != nil {
			http.Error(w, "web UI is not built", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
	return router
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	sqlDB, err := s.db.DB()
	if err != nil || sqlDB.Ping() != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("openppp2_session")
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		var session model.Session
		if err := s.db.Where("token_hash = ? AND expires_at > ?", security.TokenHash(cookie.Value), time.Now().UTC()).First(&session).Error; err != nil {
			writeError(w, http.StatusUnauthorized, "session expired")
			return
		}
		var user model.User
		if err := s.db.First(&user, session.UserID).Error; err != nil || !user.Enabled {
			writeError(w, http.StatusUnauthorized, "account disabled")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userContextKey, &user)))
	})
}

func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r).Role != "admin" {
			writeError(w, http.StatusForbidden, "administrator permission required")
			return
		}
		next(w, r)
	}
}

func (s *Server) nodeAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential := bearerToken(r)
		if credential == "" {
			writeError(w, http.StatusUnauthorized, "communication key required")
			return
		}
		var node model.Node
		nodeID := strings.TrimSpace(r.Header.Get("X-OpenPPP2-Node-ID"))
		if nodeID != "" {
			expected, err := s.communicationKey()
			if err != nil || !constantTimeEqual(credential, expected) {
				writeError(w, http.StatusUnauthorized, "invalid communication key")
				return
			}
			if err := s.db.Where("`key` = ?", nodeID).First(&node).Error; err != nil {
				writeError(w, http.StatusUnauthorized, "invalid node ID")
				return
			}
		} else {
			// Temporary compatibility for nodes that still use the former per-node credential.
			if err := s.db.Where("token_hash = ?", security.TokenHash(credential)).First(&node).Error; err != nil {
				writeError(w, http.StatusUnauthorized, "node ID required")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey("node"), &node)))
	})
}

func (s *Server) communicationSettings(w http.ResponseWriter, _ *http.Request) {
	key, err := s.communicationKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load communication key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"communicationKey": key})
}

func (s *Server) updateCommunicationSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CommunicationKey string `json:"communicationKey"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	input.CommunicationKey = strings.TrimSpace(input.CommunicationKey)
	if len(input.CommunicationKey) < 1 || len(input.CommunicationKey) > 512 {
		writeError(w, http.StatusBadRequest, "communication key must contain 1 to 512 characters")
		return
	}
	setting := model.SystemSetting{Key: communicationKeySetting, Value: input.CommunicationKey}
	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&setting).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save communication key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"communicationKey": input.CommunicationKey})
}

func (s *Server) generalSettings(w http.ResponseWriter, _ *http.Request) {
	key, err := s.communicationKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load communication key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"publicUrl":        s.publicURL(),
		"communicationKey": key,
	})
}

func (s *Server) updateGeneralSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PublicURL        string `json:"publicUrl"`
		CommunicationKey string `json:"communicationKey"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	input.PublicURL = strings.TrimRight(strings.TrimSpace(input.PublicURL), "/")
	input.CommunicationKey = strings.TrimSpace(input.CommunicationKey)
	parsed, err := url.Parse(input.PublicURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		writeError(w, http.StatusBadRequest, "public URL must be an absolute http or https URL")
		return
	}
	if len(input.PublicURL) > 2048 {
		writeError(w, http.StatusBadRequest, "public URL is too long")
		return
	}
	if len(input.CommunicationKey) < 1 || len(input.CommunicationKey) > 512 {
		writeError(w, http.StatusBadRequest, "communication key must contain 1 to 512 characters")
		return
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		for _, setting := range []model.SystemSetting{
			{Key: publicURLSetting, Value: input.PublicURL},
			{Key: communicationKeySetting, Value: input.CommunicationKey},
		} {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
			}).Create(&setting).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"publicUrl":        input.PublicURL,
		"communicationKey": input.CommunicationKey,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	var user model.User
	if err := s.db.Where("username = ?", strings.TrimSpace(input.Username)).First(&user).Error; err != nil ||
		!user.Enabled || !security.VerifyPassword(user.PasswordHash, input.Password) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, err := security.RandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create session")
		return
	}
	session := model.Session{UserID: user.ID, TokenHash: security.TokenHash(token), ExpiresAt: time.Now().UTC().Add(s.cfg.SessionTTL)}
	if err := s.db.Create(&session).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "openppp2_session", Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(s.publicURL(), "https://"),
		Expires: session.ExpiresAt,
	})
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("openppp2_session"); err == nil {
		_ = s.db.Where("token_hash = ?", security.TokenHash(cookie.Value)).Delete(&model.Session{}).Error
	}
	http.SetCookie(w, &http.Cookie{Name: "openppp2_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, currentUser(r))
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	var users, devices, nodes, online int64
	if user.Role == "admin" {
		s.db.Model(&model.User{}).Count(&users)
		s.db.Model(&model.Device{}).Count(&devices)
		s.db.Model(&model.Node{}).Count(&nodes)
		s.db.Model(&model.OnlineSession{}).Where("disconnected IS NULL AND last_heartbeat > ?", time.Now().UTC().Add(-s.cfg.NodeOfflineAfter)).Count(&online)
	} else {
		users = 1
		s.db.Model(&model.Device{}).Where("user_id = ?", user.ID).Count(&devices)
		s.db.Model(&model.Node{}).Where("published = ?", true).Count(&nodes)
		s.db.Model(&model.OnlineSession{}).
			Joins("JOIN devices ON devices.guid = online_sessions.guid").
			Where("devices.user_id = ? AND online_sessions.disconnected IS NULL AND online_sessions.last_heartbeat > ?", user.ID, time.Now().UTC().Add(-s.cfg.NodeOfflineAfter)).
			Count(&online)
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "devices": devices, "nodes": nodes, "online": online})
}

type userItem struct {
	model.User
	GroupIDs []uint64 `json:"groupIds"`
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user.Role != "admin" {
		writeJSON(w, http.StatusOK, []userItem{{User: *user, GroupIDs: userPermissionGroupIDs(s.db, user.ID)}})
		return
	}
	var users []model.User
	if err := s.db.Order("id").Find(&users).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load users")
		return
	}
	result := make([]userItem, 0, len(users))
	for _, item := range users {
		result = append(result, userItem{User: item, GroupIDs: userPermissionGroupIDs(s.db, item.ID)})
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username     string    `json:"username"`
		DisplayName  string    `json:"displayName"`
		Password     string    `json:"password"`
		Role         string    `json:"role"`
		GroupIDs     *[]uint64 `json:"groupIds"`
		TrafficLimit int64     `json:"trafficLimit"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Password) < 8 || strings.TrimSpace(input.Username) == "" {
		writeError(w, http.StatusBadRequest, "username and password of at least 8 characters are required")
		return
	}
	hash, err := security.HashPassword(input.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to hash password")
		return
	}
	if input.Role != "admin" {
		input.Role = "user"
	}
	if input.TrafficLimit == 0 {
		input.TrafficLimit = -1 // 未指定或 0 视为不限量
	}
	user := model.User{
		Username: strings.TrimSpace(input.Username), DisplayName: strings.TrimSpace(input.DisplayName),
		PasswordHash: hash, Role: input.Role, Enabled: true, TrafficLimit: input.TrafficLimit,
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		groupIDs := []uint64{}
		if input.GroupIDs != nil {
			groupIDs = *input.GroupIDs
		} else {
			var group model.PermissionGroup
			if err := tx.Where("`key` = ?", "default").First(&group).Error; err != nil {
				return err
			}
			groupIDs = []uint64{group.ID}
		}
		return replaceUserPermissionGroups(tx, user.ID, groupIDs)
	}); err != nil {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathID(w, r, "userID")
	if !ok {
		return
	}
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	var input struct {
		Enabled      *bool  `json:"enabled"`
		TrafficLimit *int64 `json:"trafficLimit"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Enabled == nil && input.TrafficLimit == nil {
		writeError(w, http.StatusBadRequest, "enabled or trafficLimit is required")
		return
	}
	if input.Enabled != nil {
		if currentUser(r).ID == user.ID && !*input.Enabled {
			writeError(w, http.StatusConflict, "cannot disable the current signed-in user")
			return
		}
		if user.Role == "admin" && !*input.Enabled {
			var enabledAdminCount int64
			s.db.Model(&model.User{}).Where("role = ? AND enabled = ?", "admin", true).Count(&enabledAdminCount)
			if enabledAdminCount <= 1 {
				writeError(w, http.StatusConflict, "the last enabled administrator cannot be disabled")
				return
			}
		}
		if user.Enabled != *input.Enabled {
			if err := s.db.Model(&user).Update("enabled", *input.Enabled).Error; err != nil {
				writeError(w, http.StatusInternalServerError, "unable to update user")
				return
			}
			user.Enabled = *input.Enabled
			s.db.Where("user_id = ?", user.ID).Delete(&model.Session{})
			s.bumpAllGroupPolicies()
		}
	}
	if input.TrafficLimit != nil {
		limit := *input.TrafficLimit
		if limit == 0 {
			limit = -1 // 0 视为不限量
		}
		if user.TrafficLimit != limit {
			if err := s.db.Model(&user).Update("traffic_limit", limit).Error; err != nil {
				writeError(w, http.StatusInternalServerError, "unable to update traffic limit")
				return
			}
			user.TrafficLimit = limit
			s.bumpAllGroupPolicies()
		}
	}
	writeJSON(w, http.StatusOK, userItem{User: user, GroupIDs: userPermissionGroupIDs(s.db, user.ID)})
}

func (s *Server) updateUserPermissionGroups(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathID(w, r, "userID")
	if !ok {
		return
	}
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	var input struct {
		GroupIDs []uint64 `json:"groupIds"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		return replaceUserPermissionGroups(tx, user.ID, input.GroupIDs)
	}); err != nil {
		writeError(w, http.StatusBadRequest, "unable to update user permission groups")
		return
	}
	s.bumpAllGroupPolicies()
	writeJSON(w, http.StatusOK, userItem{User: user, GroupIDs: uniqueUint64s(input.GroupIDs)})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathID(w, r, "userID")
	if !ok {
		return
	}
	if currentUser(r).ID == userID {
		writeError(w, http.StatusConflict, "cannot delete the current signed-in user")
		return
	}
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if user.Role == "admin" {
		var adminCount int64
		s.db.Model(&model.User{}).Where("role = ?", "admin").Count(&adminCount)
		if adminCount <= 1 {
			writeError(w, http.StatusConflict, "the last administrator cannot be deleted")
			return
		}
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var deviceIDs []uint64
		if err := tx.Model(&model.Device{}).Where("user_id = ?", user.ID).Pluck("id", &deviceIDs).Error; err != nil {
			return err
		}
		if len(deviceIDs) > 0 {
			if err := tx.Where("device_id IN ?", deviceIDs).Delete(&model.DeviceNode{}).Error; err != nil {
				return err
			}
			if err := tx.Where("device_id IN ?", deviceIDs).Delete(&model.SubscriptionToken{}).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("user_id = ?", user.ID).Delete(&model.Device{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", user.ID).Delete(&model.Session{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", user.ID).Delete(&model.UserPermissionGroup{}).Error; err != nil {
			return err
		}
		return tx.Delete(&user).Error
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to delete user")
		return
	}
	s.bumpAllGroupPolicies()
	w.WriteHeader(http.StatusNoContent)
}

type permissionGroupItem struct {
	model.PermissionGroup
	UserIDs   []uint64 `json:"userIds"`
	NodeIDs   []uint64 `json:"nodeIds"`
	GUIDCount int64    `json:"guidCount"`
}

func (s *Server) permissionGroups(w http.ResponseWriter, _ *http.Request) {
	var groups []model.PermissionGroup
	if err := s.db.Order("id").Find(&groups).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load permission groups")
		return
	}
	result := make([]permissionGroupItem, 0, len(groups))
	for _, group := range groups {
		item := permissionGroupItem{PermissionGroup: group, UserIDs: []uint64{}, NodeIDs: []uint64{}}
		var userLinks []model.UserPermissionGroup
		var nodeLinks []model.NodePermissionGroup
		s.db.Where("group_id = ?", group.ID).Find(&userLinks)
		s.db.Where("group_id = ?", group.ID).Find(&nodeLinks)
		for _, link := range userLinks {
			item.UserIDs = append(item.UserIDs, link.UserID)
		}
		for _, link := range nodeLinks {
			item.NodeIDs = append(item.NodeIDs, link.NodeID)
		}
		s.db.Model(&model.Device{}).
			Joins("JOIN user_permission_groups ON user_permission_groups.user_id = devices.user_id").
			Where("user_permission_groups.group_id = ? AND devices.enabled = ?", group.ID, true).
			Distinct("devices.guid").Count(&item.GUIDCount)
		result = append(result, item)
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createPermissionGroup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key     string   `json:"key"`
		Name    string   `json:"name"`
		Enabled *bool    `json:"enabled"`
		UserIDs []uint64 `json:"userIds"`
		NodeIDs []uint64 `json:"nodeIds"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Key = strings.TrimSpace(input.Key)
	input.Name = strings.TrimSpace(input.Name)
	if !validPermissionGroupKey(input.Key) || input.Name == "" {
		writeError(w, http.StatusBadRequest, "group key and name are required")
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	group := model.PermissionGroup{Key: input.Key, Name: input.Name, Enabled: enabled}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&group).Error; err != nil {
			return err
		}
		return replacePermissionGroupLinks(tx, group.ID, input.UserIDs, input.NodeIDs)
	})
	if err != nil {
		writeError(w, http.StatusConflict, "unable to create permission group")
		return
	}
	s.bumpAllGroupPolicies()
	writeJSON(w, http.StatusCreated, group)
}

func (s *Server) updatePermissionGroup(w http.ResponseWriter, r *http.Request) {
	groupID, ok := pathID(w, r, "groupID")
	if !ok {
		return
	}
	var group model.PermissionGroup
	if err := s.db.First(&group, groupID).Error; err != nil {
		writeError(w, http.StatusNotFound, "permission group not found")
		return
	}
	var input struct {
		Name    *string   `json:"name"`
		Enabled *bool     `json:"enabled"`
		UserIDs *[]uint64 `json:"userIds"`
		NodeIDs *[]uint64 `json:"nodeIds"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	updates := map[string]any{}
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "group name is required")
			return
		}
		updates["name"] = name
	}
	if input.Enabled != nil {
		updates["enabled"] = *input.Enabled
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if len(updates) > 0 {
			if err := tx.Model(&group).Updates(updates).Error; err != nil {
				return err
			}
		}
		if input.UserIDs != nil || input.NodeIDs != nil {
			userIDs, nodeIDs, err := permissionGroupLinkIDs(tx, group.ID)
			if err != nil {
				return err
			}
			if input.UserIDs != nil {
				userIDs = *input.UserIDs
			}
			if input.NodeIDs != nil {
				nodeIDs = *input.NodeIDs
			}
			return replacePermissionGroupLinks(tx, group.ID, userIDs, nodeIDs)
		}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to update permission group")
		return
	}
	s.bumpAllGroupPolicies()
	s.db.First(&group, group.ID)
	writeJSON(w, http.StatusOK, group)
}

func (s *Server) deletePermissionGroup(w http.ResponseWriter, r *http.Request) {
	groupID, ok := pathID(w, r, "groupID")
	if !ok {
		return
	}
	var group model.PermissionGroup
	if err := s.db.First(&group, groupID).Error; err != nil {
		writeError(w, http.StatusNotFound, "permission group not found")
		return
	}
	if group.Key == "default" {
		writeError(w, http.StatusConflict, "default permission group cannot be deleted")
		return
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("group_id = ?", group.ID).Delete(&model.UserPermissionGroup{}).Error; err != nil {
			return err
		}
		if err := tx.Where("group_id = ?", group.ID).Delete(&model.NodePermissionGroup{}).Error; err != nil {
			return err
		}
		return tx.Delete(&group).Error
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to delete permission group")
		return
	}
	s.bumpAllGroupPolicies()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	query := s.db.Model(&model.Device{})
	if user.Role != "admin" {
		query = query.Where("user_id = ?", user.ID)
	}
	var devices []model.Device
	if err := query.Order("id DESC").Find(&devices).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load devices")
		return
	}
	type item struct {
		model.Device
		OwnerName            string   `json:"ownerName"`
		DuplicateGUID        bool     `json:"duplicateGUID"`
		NodeIDs              []uint64 `json:"nodeIds"`
		PermissionGroupNames []string `json:"permissionGroupNames"`
		Online               bool     `json:"online"`
		SubscriptionURL      string   `json:"subscriptionUrl"`
		Banned               bool     `json:"banned"`
		BanReason            string   `json:"banReason"`
		BanID                *uint64  `json:"banId"`
		SelfBanned           bool     `json:"selfBanned"`
		CanUnban             bool     `json:"canUnban"`
	}
	ownerNames := map[uint64]string{}
	{
		userIDs := make([]uint64, 0, len(devices))
		for _, device := range devices {
			userIDs = append(userIDs, device.UserID)
		}
		if len(userIDs) > 0 {
			var owners []model.User
			if err := s.db.Where("id IN ?", userIDs).Find(&owners).Error; err != nil {
				writeError(w, http.StatusInternalServerError, "unable to load device owners")
				return
			}
			for _, owner := range owners {
				name := owner.DisplayName
				if name == "" {
					name = owner.Username
				}
				ownerNames[owner.ID] = name
			}
		}
	}
	// 检测重复 GUID（历史遗留数据），前端据此提示串号风险
	duplicateGUIDs := map[string]bool{}
	{
		guidCounts := map[string]int{}
		for _, device := range devices {
			guidCounts[device.GUID]++
		}
		for guid, count := range guidCounts {
			if count > 1 {
				duplicateGUIDs[guid] = true
			}
		}
	}
	result := make([]item, 0, len(devices))
	cutoff := time.Now().UTC().Add(-s.cfg.NodeOfflineAfter)
	for _, device := range devices {
		nodeIDs := make([]uint64, 0)
		availableNodesQuery(s.db, device.UserID).
			Distinct("nodes.id").Order("nodes.id").Pluck("nodes.id", &nodeIDs)
		var groups []model.PermissionGroup
		if err := s.db.Model(&model.PermissionGroup{}).
			Select("permission_groups.id, permission_groups.name").
			Joins("JOIN user_permission_groups ON user_permission_groups.group_id = permission_groups.id").
			Joins("JOIN node_permission_groups ON node_permission_groups.group_id = permission_groups.id").
			Joins("JOIN nodes ON nodes.id = node_permission_groups.node_id").
			Where("user_permission_groups.user_id = ? AND permission_groups.enabled = ? AND nodes.enabled = ? AND nodes.published = ?",
				device.UserID, true, true, true).
			Distinct("permission_groups.id, permission_groups.name").Order("permission_groups.id").Find(&groups).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load permission groups")
			return
		}
		groupNames := make([]string, 0, len(groups))
		for _, group := range groups {
			groupNames = append(groupNames, group.Name)
		}
		var count int64
		s.db.Model(&model.OnlineSession{}).Where("guid = ? AND disconnected IS NULL AND last_heartbeat > ?", device.GUID, cutoff).Count(&count)
		raw, err := s.visibleSubscriptionToken(device.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load subscription")
			return
		}
		ban, err := s.activeDeviceBan(device.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load ban status")
			return
		}
		banReason := ""
		var banID *uint64
		if ban != nil {
			banReason = ban.Reason
			banID = &ban.ID
		}
		result = append(result, item{
			Device: device, OwnerName: ownerNames[device.UserID], DuplicateGUID: duplicateGUIDs[device.GUID],
			NodeIDs: nodeIDs, PermissionGroupNames: groupNames, Online: count > 0,
			SubscriptionURL: fmt.Sprintf("%s/sub/v1/%s", s.publicURL(), raw),
			Banned: ban != nil, BanReason: banReason, BanID: banID,
			SelfBanned: ban != nil && ban.BannedByUserID == user.ID,
			CanUnban:   user.Role == "admin" || (ban != nil && ban.BannedByUserID == user.ID),
		})
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
		GUID string `json:"guid"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user := currentUser(r)
	if strings.TrimSpace(input.Name) == "" {
		writeError(w, http.StatusBadRequest, "device name is required")
		return
	}
	var err error
	if strings.TrimSpace(input.GUID) == "" {
		input.GUID, err = security.NewGUID()
	} else {
		input.GUID, err = security.NormalizeGUID(input.GUID)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// GUID 全局唯一：防止复制他人 GUID 导致会话/流量/封禁串号
	var guidCount int64
	s.db.Model(&model.Device{}).Where("guid = ?", input.GUID).Count(&guidCount)
	if guidCount > 0 {
		writeError(w, http.StatusConflict, "GUID is already in use by another device")
		return
	}
	device := model.Device{UserID: user.ID, Name: strings.TrimSpace(input.Name), GUID: input.GUID, Enabled: true}
	if err := s.db.Create(&device).Error; err != nil {
		writeError(w, http.StatusConflict, "unable to create device")
		return
	}
	token, raw, err := s.newSubscriptionToken(device.ID, "Default")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create subscription")
		return
	}
	s.bumpUserGroupNodes(user.ID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"device": device, "subscriptionToken": raw,
		"subscriptionUrl": fmt.Sprintf("%s/sub/v1/%s", s.publicURL(), raw), "token": token,
	})
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request) {
	device, ok := s.ownedDevice(w, r)
	if !ok {
		return
	}
	var input struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	updates := map[string]any{}
	if input.Name != nil && strings.TrimSpace(*input.Name) != "" {
		updates["name"] = strings.TrimSpace(*input.Name)
	}
	if input.Enabled != nil {
		updates["enabled"] = *input.Enabled
	}
	if len(updates) > 0 {
		s.db.Model(device).Updates(updates)
		s.bumpDeviceRevision(device.ID)
		s.bumpUserGroupNodes(device.UserID)
	}
	writeJSON(w, http.StatusOK, device)
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	device, ok := s.ownedDevice(w, r)
	if !ok {
		return
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("device_id = ?", device.ID).Delete(&model.DeviceNode{}).Error; err != nil {
			return err
		}
		if err := tx.Where("device_id = ?", device.ID).Delete(&model.SubscriptionToken{}).Error; err != nil {
			return err
		}
		return tx.Delete(device).Error
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to delete device")
		return
	}
	s.bumpUserGroupNodes(device.UserID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) assignDeviceNodes(w http.ResponseWriter, r *http.Request) {
	device, ok := s.ownedDevice(w, r)
	if !ok {
		return
	}
	var input struct {
		NodeIDs []uint64 `json:"nodeIds"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("device_id = ?", device.ID).Delete(&model.DeviceNode{}).Error; err != nil {
			return err
		}
		for _, nodeID := range input.NodeIDs {
			if nodeID == 0 {
				continue
			}
			var availableCount int64
			if err := availableNodesQuery(tx, currentUser(r).ID).
				Where("nodes.id = ?", nodeID).Count(&availableCount).Error; err != nil {
				return err
			}
			if availableCount == 0 {
				return fmt.Errorf("node %d is not available to current user", nodeID)
			}
			var duplicateCount int64
			if err := tx.Model(&model.DeviceNode{}).
				Joins("JOIN devices ON devices.id = device_nodes.device_id").
				Where("device_nodes.node_id = ? AND devices.guid = ? AND devices.id <> ?", nodeID, device.GUID, device.ID).
				Count(&duplicateCount).Error; err != nil {
				return err
			}
			if duplicateCount > 0 {
				return fmt.Errorf("GUID %s is already assigned to another device on node %d", device.GUID, nodeID)
			}
			if err := tx.Create(&model.DeviceNode{DeviceID: device.ID, NodeID: nodeID}).Error; err != nil {
				return err
			}
		}
		return tx.Model(&model.SubscriptionToken{}).Where("device_id = ?", device.ID).
			UpdateColumn("revision", gorm.Expr("revision + 1")).Error
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to assign nodes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deviceId": device.ID, "nodeIds": input.NodeIDs})
}

func (s *Server) createSubscriptionToken(w http.ResponseWriter, r *http.Request) {
	device, ok := s.ownedDevice(w, r)
	if !ok {
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	token, raw, err := s.newSubscriptionToken(device.ID, input.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create token")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": token, "subscriptionToken": raw,
		"subscriptionUrl": fmt.Sprintf("%s/sub/v1/%s", s.publicURL(), raw),
	})
}

func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	query := s.db.Model(&model.Node{})
	user := currentUser(r)
	if user.Role != "admin" {
		query = availableNodesQuery(s.db, user.ID)
	}
	var nodes []model.Node
	if err := query.Distinct("nodes.*").Order("nodes.id DESC").Find(&nodes).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load nodes")
		return
	}
	type item struct {
		model.Node
		GroupIDs           []uint64 `json:"groupIds"`
		WhitelistGUIDCount int64    `json:"whitelistGuidCount"`
		ConfigReady        bool     `json:"configReady"`
	}
	result := make([]item, 0, len(nodes))
	for _, node := range nodes {
		groupIDs := []uint64{}
		var links []model.NodePermissionGroup
		s.db.Where("node_id = ?", node.ID).Find(&links)
		for _, link := range links {
			groupIDs = append(groupIDs, link.GroupID)
		}
		var count int64
		whitelistDevicesQuery(s.db, node.ID).Distinct("devices.guid").Count(&count)
		result = append(result, item{
			Node: node, GroupIDs: groupIDs, WhitelistGUIDCount: count,
			ConfigReady: nodeConfigReady(node.ConfigJSON),
		})
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) availableNodes(w http.ResponseWriter, r *http.Request) {
	var nodes []model.Node
	if err := availableNodesQuery(s.db, currentUser(r).ID).
		Distinct("nodes.*").Order("nodes.id DESC").Find(&nodes).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load available nodes")
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key                 string          `json:"key"`
		Name                string          `json:"name"`
		Enabled             *bool           `json:"enabled"`
		Published           *bool           `json:"published"`
		AccessMode          string          `json:"accessMode"`
		DuplicateGUIDPolicy string          `json:"duplicateGuidPolicy"`
		Config              json.RawMessage `json:"config"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Key) == "" || strings.TrimSpace(input.Name) == "" {
		writeError(w, http.StatusBadRequest, "node key and name are required")
		return
	}
	configJSON := "{}"
	if len(input.Config) > 0 && string(input.Config) != "null" {
		if !json.Valid(input.Config) {
			writeError(w, http.StatusBadRequest, "invalid node config")
			return
		}
		configJSON = string(input.Config)
	}
	input.AccessMode = validAccessMode(input.AccessMode)
	input.DuplicateGUIDPolicy = validDuplicatePolicy(input.DuplicateGUIDPolicy)
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	published := true
	if input.Published != nil {
		published = *input.Published
	}
	legacyCredential, err := security.RandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to initialize node credential")
		return
	}
	node := model.Node{
		Key: strings.TrimSpace(input.Key), Name: strings.TrimSpace(input.Name), Enabled: enabled, Published: published,
		AccessMode: input.AccessMode, DuplicateGUIDPolicy: input.DuplicateGUIDPolicy,
		TokenHash: security.TokenHash(legacyCredential), ConfigJSON: configJSON, PolicyRevision: 1,
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&node).Error; err != nil {
			return err
		}
		var group model.PermissionGroup
		if err := tx.Where("`key` = ?", "default").First(&group).Error; err != nil {
			return err
		}
		return tx.Create(&model.NodePermissionGroup{NodeID: node.ID, GroupID: group.ID}).Error
	}); err != nil {
		writeError(w, http.StatusConflict, "node key already exists")
		return
	}
	s.bumpNodeSubscriptionRevisions(node.ID)
	writeJSON(w, http.StatusCreated, node)
}

func (s *Server) updateNode(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := pathID(w, r, "nodeID")
	if !ok {
		return
	}
	var node model.Node
	if err := s.db.First(&node, nodeID).Error; err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	var input struct {
		Name                *string          `json:"name"`
		Enabled             *bool            `json:"enabled"`
		Published           *bool            `json:"published"`
		AccessMode          *string          `json:"accessMode"`
		DuplicateGUIDPolicy *string          `json:"duplicateGuidPolicy"`
		Config              *json.RawMessage `json:"config"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	updates := map[string]any{"policy_revision": gorm.Expr("policy_revision + 1")}
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "node name is required")
			return
		}
		updates["name"] = name
	}
	if input.Enabled != nil {
		updates["enabled"] = *input.Enabled
	}
	if input.Published != nil {
		updates["published"] = *input.Published
	}
	if input.AccessMode != nil {
		updates["access_mode"] = validAccessMode(*input.AccessMode)
	}
	if input.DuplicateGUIDPolicy != nil {
		updates["duplicate_guid_policy"] = validDuplicatePolicy(*input.DuplicateGUIDPolicy)
	}
	if input.Config != nil {
		if !json.Valid(*input.Config) {
			writeError(w, http.StatusBadRequest, "invalid node config")
			return
		}
		updates["config_json"] = string(*input.Config)
	}
	if err := s.db.Model(&node).Updates(updates).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to update node")
		return
	}
	s.bumpNodeSubscriptionRevisions(node.ID)
	s.db.First(&node, node.ID)
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := pathID(w, r, "nodeID")
	if !ok {
		return
	}

	s.bumpNodeSubscriptionRevisions(nodeID)
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var node model.Node
		if err := tx.First(&node, nodeID).Error; err != nil {
			return err
		}

		deviceIDs := tx.Model(&model.DeviceNode{}).
			Select("device_id").
			Where("node_id = ?", nodeID)
		if err := tx.Model(&model.SubscriptionToken{}).
			Where("device_id IN (?)", deviceIDs).
			Update("revision", gorm.Expr("revision + 1")).Error; err != nil {
			return err
		}
		if err := tx.Where("node_id = ?", nodeID).Delete(&model.DeviceNode{}).Error; err != nil {
			return err
		}
		if err := tx.Where("node_id = ?", nodeID).Delete(&model.GUIDRule{}).Error; err != nil {
			return err
		}
		if err := tx.Where("node_id = ?", nodeID).Delete(&model.OnlineSession{}).Error; err != nil {
			return err
		}
		if err := tx.Where("node_id = ?", nodeID).Delete(&model.NodePermissionGroup{}).Error; err != nil {
			return err
		}
		return tx.Delete(&node).Error
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete node")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) nodeRules(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := pathID(w, r, "nodeID")
	if !ok {
		return
	}
	var rules []model.GUIDRule
	if err := s.db.Where("node_id = ?", nodeID).Order("id DESC").Find(&rules).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load rules")
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) createNodeRule(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := pathID(w, r, "nodeID")
	if !ok {
		return
	}
	var input struct {
		GUID      string     `json:"guid"`
		Effect    string     `json:"effect"`
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expiresAt"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	guid, err := security.NormalizeGUID(input.GUID)
	if err != nil || (input.Effect != "allow" && input.Effect != "deny") {
		writeError(w, http.StatusBadRequest, "valid GUID and allow/deny effect are required")
		return
	}
	rule := model.GUIDRule{NodeID: nodeID, GUID: guid, Effect: input.Effect, Reason: input.Reason, ExpiresAt: input.ExpiresAt}
	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_id"}, {Name: "guid"}},
		DoUpdates: clause.AssignmentColumns([]string{"effect", "reason", "expires_at", "updated_at"}),
	}).Create(&rule).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save rule")
		return
	}
	s.bumpNodeRevision(nodeID)
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) deleteNodeRule(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := pathID(w, r, "nodeID")
	if !ok {
		return
	}
	ruleID, ok := pathID(w, r, "ruleID")
	if !ok {
		return
	}
	result := s.db.Where("id = ? AND node_id = ?", ruleID, nodeID).Delete(&model.GUIDRule{})
	if result.RowsAffected == 0 {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	s.bumpNodeRevision(nodeID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) online(w http.ResponseWriter, r *http.Request) {
	cutoff := time.Now().UTC().Add(-s.cfg.NodeOfflineAfter)
	query := s.db.Model(&model.OnlineSession{}).Where("disconnected IS NULL AND last_heartbeat > ?", cutoff)
	user := currentUser(r)
	if user.Role != "admin" {
		query = query.Joins("JOIN devices ON devices.guid = online_sessions.guid").Where("devices.user_id = ?", user.ID)
	}
	var sessions []model.OnlineSession
	if err := query.Order("last_heartbeat DESC").Find(&sessions).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load online sessions")
		return
	}

	guidSet := make([]string, 0, len(sessions))
	for _, session := range sessions {
		guidSet = append(guidSet, session.GUID)
	}

	type deviceInfo struct {
		ID     uint64
		UserID uint64
		GUID   string
	}
	deviceMap := make(map[string]deviceInfo)
	if len(guidSet) > 0 {
		var devices []model.Device
		deviceQuery := s.db.Model(&model.Device{}).Where("guid IN ?", guidSet)
		if user.Role != "admin" {
			deviceQuery = deviceQuery.Where("user_id = ?", user.ID)
		}
		if err := deviceQuery.Find(&devices).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load devices")
			return
		}
		for _, device := range devices {
			deviceMap[device.GUID] = deviceInfo{ID: device.ID, UserID: device.UserID, GUID: device.GUID}
		}
	}

	ownerNames := map[uint64]string{}
	if user.Role == "admin" {
		userIDs := make([]uint64, 0, len(deviceMap))
		seen := map[uint64]bool{}
		for _, info := range deviceMap {
			if !seen[info.UserID] {
				seen[info.UserID] = true
				userIDs = append(userIDs, info.UserID)
			}
		}
		if len(userIDs) > 0 {
			var owners []model.User
			if err := s.db.Where("id IN ?", userIDs).Find(&owners).Error; err != nil {
				writeError(w, http.StatusInternalServerError, "unable to load device owners")
				return
			}
			for _, owner := range owners {
				name := owner.DisplayName
				if name == "" {
					name = owner.Username
				}
				ownerNames[owner.ID] = name
			}
		}
	}

	banMap := make(map[string]*model.DeviceBan)
	if len(guidSet) > 0 {
		var bans []model.DeviceBan
		if err := s.db.Where("guid IN ? AND unbanned_at IS NULL", guidSet).Find(&bans).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load ban status")
			return
		}
		for i := range bans {
			banMap[bans[i].GUID] = &bans[i]
		}
	}

	type item struct {
		model.OnlineSession
		DeviceID   uint64 `json:"deviceId"`
		OwnerName  string `json:"ownerName"`
		Banned     bool   `json:"banned"`
		BanReason  string `json:"banReason"`
		SelfBanned bool   `json:"selfBanned"`
		CanUnban   bool   `json:"canUnban"`
	}
	result := make([]item, 0, len(sessions))
	for _, session := range sessions {
		device := deviceMap[session.GUID]
		ban := banMap[session.GUID]
		banReason := ""
		if ban != nil {
			banReason = ban.Reason
		}
		result = append(result, item{
			OnlineSession: session,
			DeviceID:      device.ID,
			OwnerName:     ownerNames[device.UserID],
			Banned:        ban != nil,
			BanReason:     banReason,
			SelfBanned:    ban != nil && ban.BannedByUserID == user.ID,
			CanUnban:      user.Role == "admin" || (ban != nil && ban.BannedByUserID == user.ID),
		})
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) subscription(w http.ResponseWriter, r *http.Request) {
	token, device, ok := s.subscriptionIdentity(w, r)
	if !ok {
		return
	}
	var nodes []model.Node
	err := availableNodesQuery(s.db, device.UserID).
		Distinct("nodes.*").Order("nodes.id").Find(&nodes).Error
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to build subscription")
		return
	}
	type subscriptionNode struct {
		ID      string         `json:"id"`
		Name    string         `json:"name"`
		Enabled bool           `json:"enabled"`
		Config  map[string]any `json:"config"`
	}
	items := make([]subscriptionNode, 0, len(nodes))
	for _, node := range nodes {
		configMap, err := injectGUID(node.ConfigJSON, device.GUID)
		if err != nil {
			continue
		}
		items = append(items, subscriptionNode{ID: node.Key, Name: node.Name, Enabled: true, Config: configMap})
	}
	etag := fmt.Sprintf(`"revision-%d"`, token.Revision)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	now := time.Now().UTC()
	s.db.Model(token).Update("last_used", now)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"type": "openppp2-subscription", "version": 1, "revision": token.Revision,
		"name": device.Name, "nodes": items,
	})
}

func (s *Server) subscriptionNodeConfig(w http.ResponseWriter, r *http.Request) {
	_, device, ok := s.subscriptionIdentity(w, r)
	if !ok {
		return
	}
	var node model.Node
	err := availableNodesQuery(s.db, device.UserID).
		Where("`nodes`.`key` = ?", chi.URLParam(r, "nodeKey")).
		Distinct("nodes.*").First(&node).Error
	if err != nil {
		writeError(w, http.StatusNotFound, "node not available in this subscription")
		return
	}
	if !nodeConfigReady(node.ConfigJSON) {
		writeError(w, http.StatusConflict, "node configuration has not been uploaded yet")
		return
	}
	configJSON, err := injectGUIDRaw(node.ConfigJSON, device.GUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid node configuration")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, safeConfigFilename(node.Name, node.Key)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(configJSON)
}

func (s *Server) subscriptionInstallPowerShell(w http.ResponseWriter, r *http.Request) {
	_, device, ok := s.subscriptionIdentity(w, r)
	if !ok {
		return
	}
	nodes, ok := s.subscriptionNodes(w, device.UserID)
	if !ok {
		return
	}
	baseURL := fmt.Sprintf("%s/sub/v1/%s", s.publicURL(), chi.URLParam(r, "token"))
	var script strings.Builder
	script.WriteString(`$ErrorActionPreference = 'Stop'
$serverDirArgument = $args | Where-Object { $_ -like '--server-dir=*' } | Select-Object -First 1
if ($serverDirArgument) {
    $serverDir = $serverDirArgument.Substring('--server-dir='.Length).Trim('"', "'")
} else {
    $serverDir = $null
    $launchers = Get-ChildItem -LiteralPath (Get-Location) -File |
        Where-Object { $_.Extension -in '.bat', '.cmd' } |
        Sort-Object Name
    foreach ($launcher in $launchers) {
        $content = Get-Content -LiteralPath $launcher.FullName -Raw
        $match = [regex]::Match($content, '(?im)--server-dir=(?:"([^"]+)"|''([^'']+)''|([^\s"''&|]+))')
        if (-not $match.Success) { continue }
        $serverDir = @($match.Groups[1].Value, $match.Groups[2].Value, $match.Groups[3].Value) |
            Where-Object { $_ } | Select-Object -First 1
        $serverDir = $serverDir.Replace('%~dp0', ($launcher.DirectoryName + [IO.Path]::DirectorySeparatorChar))
        $serverDir = [Environment]::ExpandEnvironmentVariables($serverDir)
        if (-not [IO.Path]::IsPathRooted($serverDir)) {
            $serverDir = Join-Path $launcher.DirectoryName $serverDir
        }
        break
    }
}
if (-not $serverDir) {
    Write-Error 'No --server-dir= value was found in a .bat or .cmd file in the current PPP directory.'
    exit 2
}
$serverDir = [IO.Path]::GetFullPath($serverDir)
New-Item -ItemType Directory -Force -Path $serverDir | Out-Null
`)
	for _, node := range nodes {
		fmt.Fprintf(&script, "Invoke-WebRequest -UseBasicParsing -Uri '%s/nodes/%s/config' -OutFile (Join-Path $serverDir '%s.json')\n",
			baseURL, node.Key, safeConfigFilename(node.Name, node.Key))
	}
	fmt.Fprintf(&script, "Write-Host 'Downloaded %d OpenPPP2 configuration(s) to' $serverDir\n", len(nodes))
	writeSubscriptionScript(w, "openppp2-subscription.ps1", script.String())
}

func (s *Server) subscriptionInstallShell(w http.ResponseWriter, r *http.Request) {
	_, device, ok := s.subscriptionIdentity(w, r)
	if !ok {
		return
	}
	nodes, ok := s.subscriptionNodes(w, device.UserID)
	if !ok {
		return
	}
	baseURL := fmt.Sprintf("%s/sub/v1/%s", s.publicURL(), chi.URLParam(r, "token"))
	var script strings.Builder
	script.WriteString(`#!/bin/sh
set -eu
server_dir=''
launcher_dir=''
for argument in "$@"; do
    case "$argument" in
        --server-dir=*) server_dir=${argument#--server-dir=} ;;
    esac
done
if [ -z "$server_dir" ]; then
    for launcher in ./*.sh; do
        [ -f "$launcher" ] || continue
        server_dir=$(sed -nE 's/.*--server-dir=("([^"]+)"|'"'"'([^'"'"']+)'"'"'|([^[:space:];&|]+)).*/\2\3\4/p' "$launcher" | head -n 1)
        if [ -n "$server_dir" ]; then
            launcher_dir=$(CDPATH= cd -- "$(dirname -- "$launcher")" && pwd)
            break
        fi
    done
fi
if [ -z "$server_dir" ]; then
    echo 'No --server-dir= value was found in a .sh file in the current PPP directory.' >&2
    exit 2
fi
case "$server_dir" in
    /*) ;;
    *) server_dir="${launcher_dir:-$PWD}/$server_dir" ;;
esac
mkdir -p "$server_dir"
`)
	for _, node := range nodes {
		fmt.Fprintf(&script, "curl -fsSL '%s/nodes/%s/config' -o \"$server_dir/%s.json\"\n",
			baseURL, node.Key, safeConfigFilename(node.Name, node.Key))
	}
	fmt.Fprintf(&script, "printf 'Downloaded %d OpenPPP2 configuration(s) to %%s\\n' \"$server_dir\"\n", len(nodes))
	writeSubscriptionScript(w, "openppp2-subscription.sh", script.String())
}

func (s *Server) subscriptionNodes(w http.ResponseWriter, userID uint64) ([]model.Node, bool) {
	var nodes []model.Node
	if err := availableNodesQuery(s.db, userID).
		Distinct("nodes.*").Order("nodes.id").Find(&nodes).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to build subscription")
		return nil, false
	}
	return nodes, true
}

func safeConfigFilename(name, fallback string) string {
	name = strings.TrimSpace(name)
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`< > : " / \\ | ? *`, r) {
			return '_'
		}
		return r
	}, name)
	name = strings.Trim(name, " .")
	if name == "" {
		return fallback
	}
	return name
}

func writeSubscriptionScript(w http.ResponseWriter, filename, script string) {
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, filename))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-cache")
	_, _ = io.WriteString(w, script)
}

func (s *Server) nodePolicy(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	var rules []model.GUIDRule
	s.db.Where("node_id = ? AND (expires_at IS NULL OR expires_at > ?)", node.ID, time.Now().UTC()).Find(&rules)
	blacklist := make([]string, 0)
	whitelist := make([]string, 0)
	for _, rule := range rules {
		if rule.Effect == "deny" {
			blacklist = append(blacklist, rule.GUID)
		} else {
			whitelist = append(whitelist, rule.GUID)
		}
	}
	var disabledDevices []model.Device
	disabledDevicesQuery(s.db).Distinct("devices.*").Find(&disabledDevices)
	for _, device := range disabledDevices {
		blacklist = append(blacklist, device.GUID)
	}
	var bannedGUIDs []string
	s.db.Model(&model.DeviceBan{}).Where("unbanned_at IS NULL").Distinct().Pluck("guid", &bannedGUIDs)
	blacklist = append(blacklist, bannedGUIDs...)
	// 流量超限用户：其全部设备（含新建）均拒绝通信
	var overLimitIDs []uint64
	s.db.Model(&model.User{}).
		Where("traffic_limit > 0 AND traffic_used >= traffic_limit").
		Pluck("id", &overLimitIDs)
	if len(overLimitIDs) > 0 {
		var overDevices []model.Device
		s.db.Where("user_id IN ?", overLimitIDs).Find(&overDevices)
		for _, device := range overDevices {
			blacklist = append(blacklist, device.GUID)
		}
	}
	if node.AccessMode == "whitelist" {
		var devices []model.Device
		whitelistDevicesQuery(s.db, node.ID).Distinct("devices.*").Find(&devices)
		for _, device := range devices {
			whitelist = append(whitelist, device.GUID)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema": "openppp2-node-policy", "version": 1, "revision": node.PolicyRevision,
		"nodeId": node.Key, "enabled": node.Enabled, "accessMode": node.AccessMode,
		"duplicateGuidPolicy": node.DuplicateGUIDPolicy, "blacklist": uniqueStrings(blacklist), "whitelist": uniqueStrings(whitelist),
		"generatedAt": time.Now().UTC(),
	})
}

func (s *Server) nodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	var input struct {
		Config     json.RawMessage `json:"config"`
		ConfigText string          `json:"configText"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	now := time.Now().UTC()
	updates := map[string]any{"last_seen_at": now}
	if address := requestClientIP(r); address != "" {
		updates["last_ip"] = address
	}
	configUpdated := false
	rawConfig := input.Config
	if input.ConfigText != "" {
		rawConfig = json.RawMessage(input.ConfigText)
	}
	if len(rawConfig) > 0 && string(rawConfig) != "null" {
		configJSON, err := sanitizeNodeConfiguration(rawConfig)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid node configuration")
			return
		}
		if configJSON != node.ConfigJSON {
			updates["config_json"] = configJSON
			configUpdated = true
		}
	}
	if err := s.db.Model(node).Updates(updates).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save heartbeat")
		return
	}
	if configUpdated {
		s.bumpNodeSubscriptionRevisions(node.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"serverTime": now, "policyRevision": node.PolicyRevision, "configUpdated": configUpdated,
	})
}

func requestClientIP(r *http.Request) string {
	if address := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); address != nil {
		return address.String()
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		if address := net.ParseIP(host); address != nil {
			return address.String()
		}
	}
	if address := net.ParseIP(strings.TrimSpace(r.RemoteAddr)); address != nil {
		return address.String()
	}
	return ""
}

// accumulateUserTraffic 将节点上报的会话流量增量（双向总和）累计到所属用户。
func (s *Server) accumulateUserTraffic(guid string, rxBytes, txBytes uint64) {
	var device model.Device
	if err := s.db.Where("guid = ?", guid).First(&device).Error; err != nil {
		return
	}
	s.db.Model(&model.User{}).Where("id = ?", device.UserID).
		UpdateColumn("traffic_used", gorm.Expr("traffic_used + ?", rxBytes+txBytes))
}

func (s *Server) nodeSessions(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r)
	var input struct {
		Event    string `json:"event"`
		GUID     string `json:"guid"`
		RemoteIP string `json:"remoteIp"`
		RXBytes  uint64 `json:"rxBytes"`
		TXBytes  uint64 `json:"txBytes"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	guid, err := security.NormalizeGUID(input.GUID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid GUID")
		return
	}
	now := time.Now().UTC()
	if input.Event == "offline" {
		s.db.Model(&model.OnlineSession{}).Where("node_id = ? AND guid = ?", node.ID, guid).
			Updates(map[string]any{
				"disconnected": now, "last_heartbeat": now,
				"rx_bytes": gorm.Expr("rx_bytes + ?", input.RXBytes),
				"tx_bytes": gorm.Expr("tx_bytes + ?", input.TXBytes),
			})
		s.accumulateUserTraffic(guid, input.RXBytes, input.TXBytes)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	session := model.OnlineSession{
		NodeID: node.ID, GUID: guid, RemoteIP: input.RemoteIP, RXBytes: input.RXBytes, TXBytes: input.TXBytes,
		ConnectedAt: now, LastHeartbeat: now,
	}
	updates := map[string]any{
		"rx_bytes":       gorm.Expr("rx_bytes + ?", input.RXBytes),
		"tx_bytes":       gorm.Expr("tx_bytes + ?", input.TXBytes),
		"last_heartbeat": now,
		"disconnected":   nil,
	}
	if input.RemoteIP = strings.TrimSpace(input.RemoteIP); net.ParseIP(input.RemoteIP) != nil {
		updates["remote_ip"] = input.RemoteIP
	}
	if input.Event == "online" {
		updates["connected_at"] = now
		updates["rx_bytes"] = input.RXBytes
		updates["tx_bytes"] = input.TXBytes
	}
	err = s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_id"}, {Name: "guid"}},
		DoUpdates: clause.Assignments(updates),
	}).Create(&session).Error
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save session")
		return
	}
	if input.Event != "online" {
		s.accumulateUserTraffic(guid, input.RXBytes, input.TXBytes)
	}
	s.db.Model(&model.Device{}).Where("guid = ?", guid).Update("last_seen_at", now)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) subscriptionIdentity(w http.ResponseWriter, r *http.Request) (*model.SubscriptionToken, *model.Device, bool) {
	hash := security.TokenHash(chi.URLParam(r, "token"))
	var token model.SubscriptionToken
	if err := s.db.Where("token_hash = ? AND enabled = ?", hash, true).First(&token).Error; err != nil {
		writeError(w, http.StatusNotFound, "subscription not found")
		return nil, nil, false
	}
	var device model.Device
	if err := s.db.First(&device, token.DeviceID).Error; err != nil || !device.Enabled {
		writeError(w, http.StatusForbidden, "device disabled")
		return nil, nil, false
	}
	var user model.User
	if err := s.db.First(&user, device.UserID).Error; err != nil || !user.Enabled {
		writeError(w, http.StatusForbidden, "user disabled")
		return nil, nil, false
	}
	return &token, &device, true
}

func (s *Server) newSubscriptionToken(deviceID uint64, name string) (*model.SubscriptionToken, string, error) {
	raw, err := security.RandomToken(32)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(name) == "" {
		name = "Subscription"
	}
	token := &model.SubscriptionToken{
		DeviceID: deviceID, TokenHash: security.TokenHash(raw), RawToken: raw,
		Name: strings.TrimSpace(name), Enabled: true, Revision: 1,
	}
	if err := s.db.Create(token).Error; err != nil {
		return nil, "", err
	}
	return token, raw, nil
}

func (s *Server) communicationKey() (string, error) {
	var setting model.SystemSetting
	err := s.db.First(&setting, "`key` = ?", communicationKeySetting).Error
	if err == nil {
		return setting.Value, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}

	value := strings.TrimSpace(s.cfg.CommunicationKey)
	if value == "" {
		var randomErr error
		value, randomErr = security.RandomToken(32)
		if randomErr != nil {
			return "", randomErr
		}
	}
	setting = model.SystemSetting{Key: communicationKeySetting, Value: value}
	if err := s.db.Create(&setting).Error; err != nil {
		if lookupErr := s.db.First(&setting, "`key` = ?", communicationKeySetting).Error; lookupErr == nil {
			return setting.Value, nil
		}
		return "", err
	}
	return value, nil
}

func (s *Server) publicURL() string {
	var setting model.SystemSetting
	if err := s.db.First(&setting, "`key` = ?", publicURLSetting).Error; err == nil {
		if value := strings.TrimRight(strings.TrimSpace(setting.Value), "/"); value != "" {
			return value
		}
	}
	return strings.TrimRight(strings.TrimSpace(s.cfg.PublicURL), "/")
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func (s *Server) visibleSubscriptionToken(deviceID uint64) (string, error) {
	var token model.SubscriptionToken
	err := s.db.Where("device_id = ? AND enabled = ? AND raw_token <> ''", deviceID, true).
		Order("id DESC").First(&token).Error
	if err == nil {
		return token.RawToken, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}
	_, raw, err := s.newSubscriptionToken(deviceID, "Visible subscription")
	return raw, err
}

func (s *Server) activeDeviceBan(deviceID uint64) (*model.DeviceBan, error) {
	var ban model.DeviceBan
	err := s.db.Where("device_id = ? AND unbanned_at IS NULL", deviceID).First(&ban).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ban, nil
}

func (s *Server) accessibleDevice(w http.ResponseWriter, r *http.Request) (*model.Device, bool) {
	id, ok := pathID(w, r, "deviceID")
	if !ok {
		return nil, false
	}
	var device model.Device
	if err := s.db.First(&device, id).Error; err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return nil, false
	}
	user := currentUser(r)
	if user.Role != "admin" && device.UserID != user.ID {
		writeError(w, http.StatusForbidden, "device does not belong to current user")
		return nil, false
	}
	return &device, true
}

func (s *Server) ownedDevice(w http.ResponseWriter, r *http.Request) (*model.Device, bool) {
	id, ok := pathID(w, r, "deviceID")
	if !ok {
		return nil, false
	}
	var device model.Device
	if err := s.db.First(&device, id).Error; err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return nil, false
	}
	user := currentUser(r)
	if device.UserID != user.ID {
		writeError(w, http.StatusForbidden, "device does not belong to current user")
		return nil, false
	}
	return &device, true
}

func (s *Server) bumpDeviceRevision(deviceID uint64) {
	s.db.Model(&model.SubscriptionToken{}).Where("device_id = ?", deviceID).
		UpdateColumn("revision", gorm.Expr("revision + 1"))
}

func (s *Server) bumpNodeRevision(nodeID uint64) {
	s.db.Model(&model.Node{}).Where("id = ?", nodeID).
		UpdateColumn("policy_revision", gorm.Expr("policy_revision + 1"))
	s.bumpNodeSubscriptionRevisions(nodeID)
}

func injectGUID(raw, guid string) (map[string]any, error) {
	var value map[string]any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, err
	}
	client, _ := value["client"].(map[string]any)
	if client == nil {
		client = map[string]any{}
	}
	client["guid"] = guid
	value["client"] = client
	if server, ok := value["server"].(map[string]any); ok {
		delete(server, "management")
		delete(server, "backend-key")
	}
	return value, nil
}

func nodeConfigReady(raw string) bool {
	var value struct {
		Client json.RawMessage `json:"client"`
	}
	return json.Unmarshal([]byte(raw), &value) == nil &&
		len(value.Client) > 0 && string(value.Client) != "null"
}

func sanitizeNodeConfiguration(raw json.RawMessage) (string, error) {
	content, err := sanitizeConfigurationRaw(raw)
	return string(content), err
}

func injectGUIDRaw(raw, guid string) ([]byte, error) {
	content, err := sanitizeConfigurationRaw([]byte(raw))
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(content, &root); err != nil {
		return nil, err
	}
	client, ok := root["client"]
	if !ok {
		return nil, errors.New("client configuration is missing")
	}
	quotedGUID, _ := json.Marshal(guid)
	updatedClient, replaced, err := replaceDirectObjectValue(client, "guid", quotedGUID)
	if err != nil {
		return nil, err
	}
	if !replaced {
		updatedClient, err = insertDirectObjectValue(client, "guid", quotedGUID)
		if err != nil {
			return nil, err
		}
	}
	updated, replaced, err := replaceDirectObjectValue(content, "client", updatedClient)
	if err != nil || !replaced {
		return nil, errors.New("unable to update client configuration")
	}
	if len(updated) == 0 || updated[len(updated)-1] != '\n' {
		updated = append(updated, '\n')
	}
	return updated, nil
}

func sanitizeConfigurationRaw(raw []byte) ([]byte, error) {
	if !json.Valid(raw) {
		return nil, errors.New("invalid configuration JSON")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	server, ok := root["server"]
	if !ok {
		return append([]byte(nil), raw...), nil
	}
	sanitizedServer, _, err := replaceDirectObjectValue(server, "management", []byte("{}"))
	if err != nil {
		return nil, err
	}
	sanitizedServer, _, err = replaceDirectObjectValue(sanitizedServer, "backend-key", []byte(`""`))
	if err != nil {
		return nil, err
	}
	updated, replaced, err := replaceDirectObjectValue(raw, "server", sanitizedServer)
	if err != nil || !replaced {
		return nil, errors.New("unable to sanitize server configuration")
	}
	return updated, nil
}

func replaceDirectObjectValue(object []byte, key string, replacement []byte) ([]byte, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(object, &fields); err != nil {
		return nil, false, err
	}
	rawValue, ok := fields[key]
	if !ok {
		return append([]byte(nil), object...), false, nil
	}
	pattern := regexp.MustCompile(regexp.QuoteMeta(strconv.Quote(key)) + `[ \t\r\n]*:`)
	valueStart := -1
	for _, match := range pattern.FindAllIndex(object, -1) {
		candidate := match[1]
		for candidate < len(object) && strings.ContainsRune(" \t\r\n", rune(object[candidate])) {
			candidate++
		}
		if bytes.HasPrefix(object[candidate:], rawValue) {
			valueStart = candidate
			break
		}
	}
	if valueStart < 0 {
		return nil, false, errors.New("JSON property value location not found")
	}
	result := make([]byte, 0, len(object)-len(rawValue)+len(replacement))
	result = append(result, object[:valueStart]...)
	result = append(result, replacement...)
	result = append(result, object[valueStart+len(rawValue):]...)
	return result, true, nil
}

func insertDirectObjectValue(object []byte, key string, value []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(object)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, errors.New("target JSON value is not an object")
	}
	open := bytes.IndexByte(object, '{')
	quotedKey := strconv.Quote(key)
	body := bytes.TrimSpace(trimmed[1 : len(trimmed)-1])
	if len(body) == 0 {
		replacement := []byte(quotedKey + ": " + string(value))
		result := append([]byte(nil), object[:open+1]...)
		result = append(result, replacement...)
		result = append(result, object[open+1:]...)
		return result, nil
	}
	indent := "    "
	if match := regexp.MustCompile(`\n([ \t]+)"`).FindSubmatch(object); len(match) == 2 {
		indent = string(match[1])
	}
	var insertion string
	if bytes.Contains(object, []byte{'\n'}) {
		insertion = "\n" + indent + quotedKey + ": " + string(value) + ","
	} else {
		insertion = " " + quotedKey + ": " + string(value) + ","
	}
	result := append([]byte(nil), object[:open+1]...)
	result = append(result, insertion...)
	result = append(result, object[open+1:]...)
	return result, nil
}

var permissionGroupKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validPermissionGroupKey(value string) bool {
	return permissionGroupKeyPattern.MatchString(value)
}

func availableNodesQuery(db *gorm.DB, userID uint64) *gorm.DB {
	return db.Model(&model.Node{}).
		Joins("JOIN node_permission_groups ON node_permission_groups.node_id = nodes.id").
		Joins("JOIN user_permission_groups ON user_permission_groups.group_id = node_permission_groups.group_id").
		Joins("JOIN permission_groups ON permission_groups.id = node_permission_groups.group_id").
		Where("user_permission_groups.user_id = ? AND permission_groups.enabled = ? AND nodes.enabled = ? AND nodes.published = ?",
			userID, true, true, true)
}

func whitelistDevicesQuery(db *gorm.DB, nodeID uint64) *gorm.DB {
	return db.Model(&model.Device{}).
		Joins("JOIN users ON users.id = devices.user_id").
		Joins("JOIN user_permission_groups ON user_permission_groups.user_id = devices.user_id").
		Joins("JOIN node_permission_groups ON node_permission_groups.group_id = user_permission_groups.group_id").
		Joins("JOIN permission_groups ON permission_groups.id = user_permission_groups.group_id").
		Where("node_permission_groups.node_id = ? AND permission_groups.enabled = ? AND users.enabled = ? AND devices.enabled = ?",
			nodeID, true, true, true)
}

func disabledDevicesQuery(db *gorm.DB) *gorm.DB {
	return db.Model(&model.Device{}).
		Joins("JOIN users ON users.id = devices.user_id").
		Where("users.enabled = ?", false)
}

func permissionGroupLinkIDs(tx *gorm.DB, groupID uint64) ([]uint64, []uint64, error) {
	var userLinks []model.UserPermissionGroup
	if err := tx.Where("group_id = ?", groupID).Find(&userLinks).Error; err != nil {
		return nil, nil, err
	}
	var nodeLinks []model.NodePermissionGroup
	if err := tx.Where("group_id = ?", groupID).Find(&nodeLinks).Error; err != nil {
		return nil, nil, err
	}
	userIDs := make([]uint64, 0, len(userLinks))
	nodeIDs := make([]uint64, 0, len(nodeLinks))
	for _, link := range userLinks {
		userIDs = append(userIDs, link.UserID)
	}
	for _, link := range nodeLinks {
		nodeIDs = append(nodeIDs, link.NodeID)
	}
	return userIDs, nodeIDs, nil
}

func userPermissionGroupIDs(db *gorm.DB, userID uint64) []uint64 {
	var links []model.UserPermissionGroup
	if err := db.Where("user_id = ?", userID).Order("group_id").Find(&links).Error; err != nil {
		return []uint64{}
	}
	groupIDs := make([]uint64, 0, len(links))
	for _, link := range links {
		groupIDs = append(groupIDs, link.GroupID)
	}
	return groupIDs
}

func replaceUserPermissionGroups(tx *gorm.DB, userID uint64, groupIDs []uint64) error {
	groupIDs = uniqueUint64s(groupIDs)
	if len(groupIDs) > 0 {
		var count int64
		if err := tx.Model(&model.PermissionGroup{}).Where("id IN ?", groupIDs).Count(&count).Error; err != nil {
			return err
		}
		if count != int64(len(groupIDs)) {
			return errors.New("one or more permission groups do not exist")
		}
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.UserPermissionGroup{}).Error; err != nil {
		return err
	}
	for _, groupID := range groupIDs {
		if err := tx.Create(&model.UserPermissionGroup{UserID: userID, GroupID: groupID}).Error; err != nil {
			return err
		}
	}
	return nil
}

func replacePermissionGroupLinks(tx *gorm.DB, groupID uint64, userIDs, nodeIDs []uint64) error {
	userIDs = uniqueUint64s(userIDs)
	nodeIDs = uniqueUint64s(nodeIDs)
	if len(userIDs) > 0 {
		var count int64
		if err := tx.Model(&model.User{}).Where("id IN ?", userIDs).Count(&count).Error; err != nil {
			return err
		}
		if count != int64(len(userIDs)) {
			return errors.New("one or more users do not exist")
		}
	}
	if len(nodeIDs) > 0 {
		var count int64
		if err := tx.Model(&model.Node{}).Where("id IN ?", nodeIDs).Count(&count).Error; err != nil {
			return err
		}
		if count != int64(len(nodeIDs)) {
			return errors.New("one or more nodes do not exist")
		}
	}
	if err := tx.Where("group_id = ?", groupID).Delete(&model.UserPermissionGroup{}).Error; err != nil {
		return err
	}
	if err := tx.Where("group_id = ?", groupID).Delete(&model.NodePermissionGroup{}).Error; err != nil {
		return err
	}
	for _, userID := range userIDs {
		if err := tx.Create(&model.UserPermissionGroup{UserID: userID, GroupID: groupID}).Error; err != nil {
			return err
		}
	}
	for _, nodeID := range nodeIDs {
		if err := tx.Create(&model.NodePermissionGroup{NodeID: nodeID, GroupID: groupID}).Error; err != nil {
			return err
		}
	}
	return nil
}

func uniqueUint64s(values []uint64) []uint64 {
	seen := make(map[uint64]struct{}, len(values))
	result := make([]uint64, 0, len(values))
	for _, value := range values {
		if value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (s *Server) bumpAllGroupPolicies() {
	s.db.Model(&model.Node{}).Where("1 = 1").
		UpdateColumn("policy_revision", gorm.Expr("policy_revision + 1"))
	s.db.Model(&model.SubscriptionToken{}).Where("1 = 1").
		UpdateColumn("revision", gorm.Expr("revision + 1"))
}

func (s *Server) bumpNodeSubscriptionRevisions(nodeID uint64) {
	userIDs := s.db.Model(&model.UserPermissionGroup{}).
		Select("user_permission_groups.user_id").
		Joins("JOIN node_permission_groups ON node_permission_groups.group_id = user_permission_groups.group_id").
		Where("node_permission_groups.node_id = ?", nodeID)
	deviceIDs := s.db.Model(&model.Device{}).Select("id").Where("user_id IN (?)", userIDs)
	s.db.Model(&model.SubscriptionToken{}).Where("device_id IN (?)", deviceIDs).
		UpdateColumn("revision", gorm.Expr("revision + 1"))
}

func (s *Server) bumpUserGroupNodes(userID uint64) {
	s.db.Model(&model.Node{}).
		Where("id IN (?)",
			s.db.Model(&model.NodePermissionGroup{}).
				Select("node_id").
				Where("group_id IN (?)",
					s.db.Model(&model.UserPermissionGroup{}).
						Select("group_id").
						Where("user_id = ?", userID))).
		UpdateColumn("policy_revision", gorm.Expr("policy_revision + 1"))
}

func validAccessMode(value string) string {
	if value == "whitelist" {
		return "whitelist"
	}
	return "blacklist"
}

func validDuplicatePolicy(value string) string {
	if value == "reject_new" {
		return "reject_new"
	}
	return "replace_old"
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func currentUser(r *http.Request) *model.User {
	return r.Context().Value(userContextKey).(*model.User)
}

func currentNode(r *http.Request) *model.Node {
	return r.Context().Value(contextKey("node")).(*model.Node)
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(value) < 8 || !strings.EqualFold(value[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(value[7:])
}

func pathID(w http.ResponseWriter, r *http.Request, key string) (uint64, bool) {
	id, err := strconv.ParseUint(chi.URLParam(r, key), 10, 64)
	if err != nil || id == 0 {
		writeError(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "request must contain one JSON object")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeIndentedJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ")
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func (s *Server) batchBanDevices(w http.ResponseWriter, r *http.Request) {
	var input struct {
		IDs    []uint64 `json:"ids"`
		Reason string   `json:"reason"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "device ids are required")
		return
	}
	user := currentUser(r)
	query := s.db.Model(&model.Device{})
	if user.Role != "admin" {
		query = query.Where("user_id = ?", user.ID)
	}
	var devices []model.Device
	if err := query.Where("id IN ?", input.IDs).Find(&devices).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load devices")
		return
	}
	reason := strings.TrimSpace(input.Reason)
	banned := 0
	for _, device := range devices {
		existing, err := s.activeDeviceBan(device.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to check ban status")
			return
		}
		if existing != nil {
			continue
		}
		ban := model.DeviceBan{
			DeviceID:       device.ID,
			GUID:           device.GUID,
			BannedByUserID: user.ID,
			BannedByRole:   user.Role,
			Reason:         reason,
		}
		if err := s.db.Create(&ban).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "unable to ban device")
			return
		}
		banned++
	}
	if banned > 0 {
		s.bumpAllGroupPolicies()
	}
	writeJSON(w, http.StatusOK, map[string]any{"banned": banned})
}

func (s *Server) batchUnbanDevices(w http.ResponseWriter, r *http.Request) {
	var input struct {
		IDs []uint64 `json:"ids"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "device ids are required")
		return
	}
	user := currentUser(r)
	query := s.db.Model(&model.DeviceBan{}).Where("unbanned_at IS NULL")
	if user.Role != "admin" {
		query = query.Where("banned_by_user_id = ?", user.ID)
	}
	var bans []model.DeviceBan
	if err := query.Where("device_id IN ?", input.IDs).Find(&bans).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load bans")
		return
	}
	now := time.Now().UTC()
	unbanned := 0
	for _, ban := range bans {
		if err := s.db.Model(&ban).Updates(map[string]any{
			"unbanned_at":         now,
			"unbanned_by_user_id": user.ID,
		}).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "unable to unban device")
			return
		}
		unbanned++
	}
	if unbanned > 0 {
		s.bumpAllGroupPolicies()
	}
	writeJSON(w, http.StatusOK, map[string]any{"unbanned": unbanned})
}

func (s *Server) banDevice(w http.ResponseWriter, r *http.Request) {
	device, ok := s.accessibleDevice(w, r)
	if !ok {
		return
	}
	var input struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user := currentUser(r)
	existing, err := s.activeDeviceBan(device.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to check ban status")
		return
	}
	if existing != nil {
		writeError(w, http.StatusConflict, "device is already banned")
		return
	}
	ban := model.DeviceBan{
		DeviceID:       device.ID,
		GUID:           device.GUID,
		BannedByUserID: user.ID,
		BannedByRole:   user.Role,
		Reason:         strings.TrimSpace(input.Reason),
	}
	if err := s.db.Create(&ban).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to ban device")
		return
	}
	s.bumpAllGroupPolicies()
	writeJSON(w, http.StatusCreated, ban)
}

func (s *Server) unbanDevice(w http.ResponseWriter, r *http.Request) {
	device, ok := s.accessibleDevice(w, r)
	if !ok {
		return
	}
	ban, err := s.activeDeviceBan(device.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to check ban status")
		return
	}
	if ban == nil {
		writeError(w, http.StatusNotFound, "device is not banned")
		return
	}
	user := currentUser(r)
	if user.Role != "admin" && ban.BannedByUserID != user.ID {
		writeError(w, http.StatusForbidden, "only the user who banned this device or an administrator can unban it")
		return
	}
	now := time.Now().UTC()
	updates := map[string]any{
		"unbanned_at":         now,
		"unbanned_by_user_id": user.ID,
	}
	if err := s.db.Model(ban).Updates(updates).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to unban device")
		return
	}
	ban.UnbannedAt = &now
	ban.UnbannedByUserID = &user.ID
	s.bumpAllGroupPolicies()
	writeJSON(w, http.StatusOK, ban)
}

func (s *Server) deviceBans(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	query := s.db.Model(&model.DeviceBan{}).Where("unbanned_at IS NULL")
	if user.Role != "admin" {
		query = query.Joins("JOIN devices ON devices.id = device_bans.device_id").Where("devices.user_id = ?", user.ID)
	}
	var bans []model.DeviceBan
	if err := query.Order("device_bans.id DESC").Find(&bans).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load bans")
		return
	}
	type item struct {
		model.DeviceBan
		DeviceName string `json:"deviceName"`
		Username   string `json:"username"`
		SelfBanned bool   `json:"selfBanned"`
		CanUnban   bool   `json:"canUnban"`
	}
	result := make([]item, 0, len(bans))
	for _, ban := range bans {
		var device model.Device
		deviceName := ""
		if err := s.db.First(&device, ban.DeviceID).Error; err == nil {
			deviceName = device.Name
		}
		username := ""
		var banner model.User
		if err := s.db.First(&banner, ban.BannedByUserID).Error; err == nil {
			username = banner.Username
		}
		result = append(result, item{
			DeviceBan: ban, DeviceName: deviceName, Username: username,
			SelfBanned: ban.BannedByUserID == user.ID,
			CanUnban:   user.Role == "admin" || ban.BannedByUserID == user.ID,
		})
	}
	writeJSON(w, http.StatusOK, result)
}

