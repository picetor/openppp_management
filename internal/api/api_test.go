package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/openppp2/openppp2-management/internal/config"
	"github.com/openppp2/openppp2-management/internal/database"
	"github.com/openppp2/openppp2-management/internal/model"
	"github.com/openppp2/openppp2-management/internal/security"
	"gorm.io/gorm"
)

func TestSubscriptionAndNodePolicyFlow(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:api-test?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(db); err != nil {
		t.Fatal(err)
	}
	passwordHash, err := security.HashPassword("test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	admin := model.User{
		Username: "admin", DisplayName: "Admin", PasswordHash: passwordHash, Role: "admin", Enabled: true,
	}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.EnsurePermissionDefaults(db); err != nil {
		t.Fatal(err)
	}

	communicationKey := "test-global-communication-key"
	handler := New(db, config.Config{
		PublicURL: "http://manager.test", CommunicationKey: communicationKey,
		SessionTTL: time.Hour, NodeOfflineAfter: 90 * time.Second,
	})

	login := performJSON(t, handler, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"username": "admin", "password": "test-password-123"}, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", login.Code, login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	settings := performJSONWithCookie(t, handler, http.MethodGet, "/api/v1/settings/communication", nil, cookie)
	var settingsResult struct {
		CommunicationKey string `json:"communicationKey"`
	}
	decodeRecorder(t, settings, &settingsResult)
	if settingsResult.CommunicationKey != communicationKey {
		t.Fatalf("unexpected communication key %q", settingsResult.CommunicationKey)
	}
	updatedSettings := performJSONWithCookie(t, handler, http.MethodPut, "/api/v1/settings/communication",
		map[string]any{"communicationKey": "updated-global-communication-key"}, cookie)
	if updatedSettings.Code != http.StatusOK {
		t.Fatalf("update communication key failed: %d %s", updatedSettings.Code, updatedSettings.Body.String())
	}
	communicationKey = "updated-global-communication-key"
	generalSettings := performJSONWithCookie(t, handler, http.MethodPut, "/api/v1/settings/general",
		map[string]any{
			"publicUrl":        "https://public.manager.test/",
			"communicationKey": communicationKey,
		}, cookie)
	if generalSettings.Code != http.StatusOK {
		t.Fatalf("update general settings failed: %d %s", generalSettings.Code, generalSettings.Body.String())
	}

	nodeResponse := performJSONWithCookie(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"key": "hk01", "name": "Hong Kong 01", "enabled": true, "published": true,
		"accessMode": "blacklist", "duplicateGuidPolicy": "replace_old",
		"config": map[string]any{
			"key":    map[string]any{"protocol": "aes-128-cfb", "protocol-key": "pk"},
			"client": map[string]any{"server": "ppp://hk.example.com:20000/"},
		},
	}, cookie)
	if nodeResponse.Code != http.StatusCreated {
		t.Fatalf("create node failed: %d %s", nodeResponse.Code, nodeResponse.Body.String())
	}
	var nodeResult model.Node
	decodeRecorder(t, nodeResponse, &nodeResult)

	deviceResponse := performJSONWithCookie(t, handler, http.MethodPost, "/api/v1/devices",
		map[string]any{"name": "Android Phone", "guid": ""}, cookie)
	if deviceResponse.Code != http.StatusCreated {
		t.Fatalf("create device failed: %d %s", deviceResponse.Code, deviceResponse.Body.String())
	}
	var deviceResult struct {
		Device            model.Device `json:"device"`
		SubscriptionToken string       `json:"subscriptionToken"`
	}
	decodeRecorder(t, deviceResponse, &deviceResult)
	if deviceResult.Device.UserID != admin.ID {
		t.Fatalf("device owner %d does not match current user %d", deviceResult.Device.UserID, admin.ID)
	}

	deviceList := performJSONWithCookie(t, handler, http.MethodGet, "/api/v1/devices", nil, cookie)
	if deviceList.Code != http.StatusOK {
		t.Fatalf("device list failed: %d %s", deviceList.Code, deviceList.Body.String())
	}
	var visibleDevices []struct {
		model.Device
		SubscriptionURL string   `json:"subscriptionUrl"`
		NodeIDs         []uint64 `json:"nodeIds"`
	}
	decodeRecorder(t, deviceList, &visibleDevices)
	if len(visibleDevices) != 1 ||
		!strings.HasPrefix(visibleDevices[0].SubscriptionURL, "https://public.manager.test/sub/v1/") ||
		!strings.HasSuffix(visibleDevices[0].SubscriptionURL, deviceResult.SubscriptionToken) {
		t.Fatalf("subscription URL is not visible on device: %+v", visibleDevices)
	}
	if len(visibleDevices[0].NodeIDs) != 1 || visibleDevices[0].NodeIDs[0] != nodeResult.ID {
		t.Fatalf("device subscription nodes were not derived from permission groups: %+v", visibleDevices[0].NodeIDs)
	}

	subscription := httptest.NewRecorder()
	handler.ServeHTTP(subscription, httptest.NewRequest(http.MethodGet,
		"/sub/v1/"+deviceResult.SubscriptionToken, nil))
	if subscription.Code != http.StatusOK {
		t.Fatalf("subscription failed: %d %s", subscription.Code, subscription.Body.String())
	}
	var document struct {
		Type  string `json:"type"`
		Nodes []struct {
			Config struct {
				Client struct {
					GUID string `json:"guid"`
				} `json:"client"`
			} `json:"config"`
		} `json:"nodes"`
	}
	decodeRecorder(t, subscription, &document)
	if document.Type != "openppp2-subscription" || len(document.Nodes) != 1 {
		t.Fatalf("unexpected subscription: %+v", document)
	}
	if document.Nodes[0].Config.Client.GUID != deviceResult.Device.GUID {
		t.Fatalf("subscription GUID %q does not match device %q",
			document.Nodes[0].Config.Client.GUID, deviceResult.Device.GUID)
	}
	configDownload := httptest.NewRecorder()
	handler.ServeHTTP(configDownload, httptest.NewRequest(http.MethodGet,
		"/sub/v1/"+deviceResult.SubscriptionToken+"/nodes/"+nodeResult.Key+"/config", nil))
	if configDownload.Code != http.StatusOK ||
		!strings.Contains(configDownload.Header().Get("Content-Disposition"), "appsettings.json") {
		t.Fatalf("node configuration download failed: %d %q", configDownload.Code, configDownload.Body.String())
	}

	policyRequest := httptest.NewRequest(http.MethodGet, "/api/v1/node/policy", nil)
	policyRequest.Header.Set("Authorization", "Bearer "+communicationKey)
	policyRequest.Header.Set("X-OpenPPP2-Node-ID", nodeResult.Key)
	policy := httptest.NewRecorder()
	handler.ServeHTTP(policy, policyRequest)
	if policy.Code != http.StatusOK {
		t.Fatalf("node policy failed: %d %s", policy.Code, policy.Body.String())
	}
	var policyDocument struct {
		AccessMode string `json:"accessMode"`
	}
	decodeRecorder(t, policy, &policyDocument)
	if policyDocument.AccessMode != "blacklist" {
		t.Fatalf("expected blacklist mode, got %q", policyDocument.AccessMode)
	}
	originalConfig := `{
  "z-last": 1,
  "client": {
    "server": "ppp://uploaded.example.com:20000/",
    "guid": "old-guid"
  },
  "server": {
    "management": {"communication-key": "must-not-be-published"},
    "backend-key": "must-not-be-published",
    "log": "/dev/null"
  },
  "a-first": 2
}`
	heartbeatBody, err := json.Marshal(map[string]any{"configText": originalConfig})
	if err != nil {
		t.Fatal(err)
	}
	heartbeatRequest := httptest.NewRequest(http.MethodPost, "/api/v1/node/heartbeat",
		bytes.NewReader(heartbeatBody))
	heartbeatRequest.Header.Set("Content-Type", "application/json")
	heartbeatRequest.Header.Set("Authorization", "Bearer "+communicationKey)
	heartbeatRequest.Header.Set("X-OpenPPP2-Node-ID", nodeResult.Key)
	heartbeatRequest.Header.Set("CF-Connecting-IP", "203.0.113.25")
	heartbeat := httptest.NewRecorder()
	handler.ServeHTTP(heartbeat, heartbeatRequest)
	if heartbeat.Code != http.StatusOK {
		t.Fatalf("node heartbeat failed: %d %s", heartbeat.Code, heartbeat.Body.String())
	}
	var heartbeatNode model.Node
	if err := db.First(&heartbeatNode, nodeResult.ID).Error; err != nil {
		t.Fatal(err)
	}
	if heartbeatNode.LastIP != "203.0.113.25" {
		t.Fatalf("unexpected heartbeat IP: %q", heartbeatNode.LastIP)
	}
	if err := db.First(&nodeResult, nodeResult.ID).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nodeResult.ConfigJSON, "must-not-be-published") ||
		!strings.Contains(nodeResult.ConfigJSON, "uploaded.example.com") {
		t.Fatalf("uploaded node configuration was not sanitized: %s", nodeResult.ConfigJSON)
	}
	if !(strings.Index(nodeResult.ConfigJSON, `"z-last"`) <
		strings.Index(nodeResult.ConfigJSON, `"client"`) &&
		strings.Index(nodeResult.ConfigJSON, `"client"`) <
			strings.Index(nodeResult.ConfigJSON, `"server"`) &&
		strings.Index(nodeResult.ConfigJSON, `"server"`) <
			strings.Index(nodeResult.ConfigJSON, `"a-first"`)) {
		t.Fatalf("uploaded node configuration order changed: %s", nodeResult.ConfigJSON)
	}

	preservedDownload := httptest.NewRecorder()
	handler.ServeHTTP(preservedDownload, httptest.NewRequest(http.MethodGet,
		"/sub/v1/"+deviceResult.SubscriptionToken+"/nodes/"+nodeResult.Key+"/config", nil))
	preservedConfig := preservedDownload.Body.String()
	if preservedDownload.Code != http.StatusOK ||
		!strings.Contains(preservedConfig, `"guid": "`+deviceResult.Device.GUID+`"`) ||
		strings.Contains(preservedConfig, "old-guid") ||
		!strings.Contains(preservedConfig, `"management": {}`) ||
		!strings.Contains(preservedConfig, `"backend-key": ""`) {
		t.Fatalf("node configuration was not preserved with only the GUID changed: %d %s",
			preservedDownload.Code, preservedConfig)
	}
	if !(strings.Index(preservedConfig, `"z-last"`) <
		strings.Index(preservedConfig, `"client"`) &&
		strings.Index(preservedConfig, `"client"`) <
			strings.Index(preservedConfig, `"server"`) &&
		strings.Index(preservedConfig, `"server"`) <
			strings.Index(preservedConfig, `"a-first"`)) {
		t.Fatalf("downloaded node configuration order changed: %s", preservedConfig)
	}

	powerShellScript := httptest.NewRecorder()
	handler.ServeHTTP(powerShellScript, httptest.NewRequest(http.MethodGet,
		"/sub/v1/"+deviceResult.SubscriptionToken+"/scripts/install.ps1", nil))
	if powerShellScript.Code != http.StatusOK ||
		!strings.Contains(powerShellScript.Body.String(), "--server-dir=") ||
		!strings.Contains(powerShellScript.Body.String(), "hk01.json") {
		t.Fatalf("unexpected PowerShell subscription script: %d %s",
			powerShellScript.Code, powerShellScript.Body.String())
	}
	shellScript := httptest.NewRecorder()
	handler.ServeHTTP(shellScript, httptest.NewRequest(http.MethodGet,
		"/sub/v1/"+deviceResult.SubscriptionToken+"/scripts/install.sh", nil))
	if shellScript.Code != http.StatusOK ||
		!strings.Contains(shellScript.Body.String(), "--server-dir=") ||
		!strings.Contains(shellScript.Body.String(), "hk01.json") {
		t.Fatalf("unexpected shell subscription script: %d %s",
			shellScript.Code, shellScript.Body.String())
	}

	updateNode := performJSONWithCookie(t, handler, http.MethodPatch,
		"/api/v1/nodes/"+uintString(nodeResult.ID),
		map[string]any{
			"name": "Hong Kong Updated", "enabled": true, "published": true,
			"accessMode": "whitelist", "duplicateGuidPolicy": "reject_new",
			"config": map[string]any{"client": map[string]any{"server": "ppp://updated.example.com:20000/"}},
		}, cookie)
	if updateNode.Code != http.StatusOK {
		t.Fatalf("update node failed: %d %s", updateNode.Code, updateNode.Body.String())
	}
	var updatedNode model.Node
	decodeRecorder(t, updateNode, &updatedNode)
	if updatedNode.Name != "Hong Kong Updated" || updatedNode.AccessMode != "whitelist" ||
		updatedNode.DuplicateGUIDPolicy != "reject_new" || !updatedNode.Enabled || !updatedNode.Published {
		t.Fatalf("unexpected updated node: %+v", updatedNode)
	}

	whitelistRequest := httptest.NewRequest(http.MethodGet, "/api/v1/node/policy", nil)
	whitelistRequest.Header.Set("Authorization", "Bearer "+communicationKey)
	whitelistRequest.Header.Set("X-OpenPPP2-Node-ID", nodeResult.Key)
	whitelistPolicy := httptest.NewRecorder()
	handler.ServeHTTP(whitelistPolicy, whitelistRequest)
	var whitelistDocument struct {
		AccessMode string   `json:"accessMode"`
		Whitelist  []string `json:"whitelist"`
	}
	decodeRecorder(t, whitelistPolicy, &whitelistDocument)
	if whitelistDocument.AccessMode != "whitelist" ||
		!containsString(whitelistDocument.Whitelist, deviceResult.Device.GUID) {
		t.Fatalf("group device GUID missing from whitelist policy: %+v", whitelistDocument)
	}

	groupsResponse := performJSONWithCookie(t, handler, http.MethodGet, "/api/v1/permission-groups", nil, cookie)
	if groupsResponse.Code != http.StatusOK {
		t.Fatalf("permission groups failed: %d %s", groupsResponse.Code, groupsResponse.Body.String())
	}
	var groups []permissionGroupItem
	decodeRecorder(t, groupsResponse, &groups)
	if len(groups) != 1 || groups[0].Key != "default" {
		t.Fatalf("unexpected default permission groups: %+v", groups)
	}

	userResponse := performJSONWithCookie(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "member", "displayName": "Member", "password": "member-password",
		"role": "user", "groupIds": []uint64{groups[0].ID},
	}, cookie)
	if userResponse.Code != http.StatusCreated {
		t.Fatalf("create user failed: %d %s", userResponse.Code, userResponse.Body.String())
	}
	var member model.User
	decodeRecorder(t, userResponse, &member)
	updateUserGroups := performJSONWithCookie(t, handler, http.MethodPut,
		"/api/v1/users/"+uintString(member.ID)+"/permission-groups",
		map[string]any{"groupIds": []uint64{}}, cookie)
	if updateUserGroups.Code != http.StatusOK {
		t.Fatalf("update user groups failed: %d %s", updateUserGroups.Code, updateUserGroups.Body.String())
	}
	memberDevice := model.Device{
		UserID: member.ID, Name: "Member device", GUID: "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}", Enabled: true,
	}
	if err := db.Create(&memberDevice).Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&Server{db: db, cfg: config.Config{PublicURL: "http://manager.test"}}).
		newSubscriptionToken(memberDevice.ID, "Member subscription"); err != nil {
		t.Fatal(err)
	}
	disableUser := performJSONWithCookie(t, handler, http.MethodPatch,
		"/api/v1/users/"+uintString(member.ID), map[string]any{"enabled": false}, cookie)
	if disableUser.Code != http.StatusOK {
		t.Fatalf("disable user failed: %d %s", disableUser.Code, disableUser.Body.String())
	}
	disabledPolicyRequest := httptest.NewRequest(http.MethodGet, "/api/v1/node/policy", nil)
	disabledPolicyRequest.Header.Set("Authorization", "Bearer "+communicationKey)
	disabledPolicyRequest.Header.Set("X-OpenPPP2-Node-ID", nodeResult.Key)
	disabledPolicy := httptest.NewRecorder()
	handler.ServeHTTP(disabledPolicy, disabledPolicyRequest)
	var disabledPolicyDocument struct {
		Blacklist []string `json:"blacklist"`
	}
	decodeRecorder(t, disabledPolicy, &disabledPolicyDocument)
	if !containsString(disabledPolicyDocument.Blacklist, memberDevice.GUID) {
		t.Fatalf("disabled user GUID missing from blacklist policy: %+v", disabledPolicyDocument)
	}
	enableUser := performJSONWithCookie(t, handler, http.MethodPatch,
		"/api/v1/users/"+uintString(member.ID), map[string]any{"enabled": true}, cookie)
	if enableUser.Code != http.StatusOK {
		t.Fatalf("enable user failed: %d %s", enableUser.Code, enableUser.Body.String())
	}
	deleteUser := performJSONWithCookie(t, handler, http.MethodDelete,
		"/api/v1/users/"+uintString(member.ID), nil, cookie)
	if deleteUser.Code != http.StatusNoContent {
		t.Fatalf("delete user failed: %d %s", deleteUser.Code, deleteUser.Body.String())
	}
	for name, target := range map[string]any{
		"user": &model.User{}, "device": &model.Device{}, "subscription": &model.SubscriptionToken{},
	} {
		var count int64
		query := db.Model(target)
		if name == "user" {
			query = query.Where("id = ?", member.ID)
		} else if name == "device" {
			query = query.Where("user_id = ?", member.ID)
		} else {
			query = query.Where("device_id = ?", memberDevice.ID)
		}
		if err := query.Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("deleted user still has %s records: count=%d err=%v", name, count, err)
		}
	}

	availableResponse := performJSONWithCookie(t, handler, http.MethodGet, "/api/v1/available-nodes", nil, cookie)
	var available []model.Node
	decodeRecorder(t, availableResponse, &available)
	if len(available) != 1 || available[0].ID != nodeResult.ID {
		t.Fatalf("group node is not available: %+v", available)
	}

	removeUserFromGroup := performJSONWithCookie(t, handler, http.MethodPatch,
		"/api/v1/permission-groups/"+uintString(groups[0].ID),
		map[string]any{"userIds": []uint64{}, "nodeIds": []uint64{nodeResult.ID}}, cookie)
	if removeUserFromGroup.Code != http.StatusOK {
		t.Fatalf("update permission group failed: %d %s", removeUserFromGroup.Code, removeUserFromGroup.Body.String())
	}
	availableResponse = performJSONWithCookie(t, handler, http.MethodGet, "/api/v1/available-nodes", nil, cookie)
	decodeRecorder(t, availableResponse, &available)
	if len(available) != 0 {
		t.Fatalf("node remained available after user left group: %+v", available)
	}

	emptyWhitelistRequest := httptest.NewRequest(http.MethodGet, "/api/v1/node/policy", nil)
	emptyWhitelistRequest.Header.Set("Authorization", "Bearer "+communicationKey)
	emptyWhitelistRequest.Header.Set("X-OpenPPP2-Node-ID", nodeResult.Key)
	emptyWhitelistPolicy := httptest.NewRecorder()
	handler.ServeHTTP(emptyWhitelistPolicy, emptyWhitelistRequest)
	decodeRecorder(t, emptyWhitelistPolicy, &whitelistDocument)
	if len(whitelistDocument.Whitelist) != 0 {
		t.Fatalf("whitelist still contains group GUIDs: %+v", whitelistDocument.Whitelist)
	}

	if err := db.Create(&model.GUIDRule{
		NodeID: nodeResult.ID, GUID: deviceResult.Device.GUID, Effect: "deny",
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.OnlineSession{
		NodeID: nodeResult.ID, GUID: deviceResult.Device.GUID,
		ConnectedAt: time.Now(), LastHeartbeat: time.Now(),
	}).Error; err != nil {
		t.Fatal(err)
	}

	deleteNode := performJSONWithCookie(t, handler, http.MethodDelete,
		"/api/v1/nodes/"+uintString(nodeResult.ID), nil, cookie)
	if deleteNode.Code != http.StatusNoContent {
		t.Fatalf("delete node failed: %d %s", deleteNode.Code, deleteNode.Body.String())
	}
	for name, target := range map[string]any{
		"nodes": &model.Node{}, "assignments": &model.DeviceNode{},
		"rules": &model.GUIDRule{}, "online sessions": &model.OnlineSession{},
	} {
		var count int64
		if err := db.Model(target).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("expected deleted node %s to be empty, got %d", name, count)
		}
	}

	deletedPolicyRequest := httptest.NewRequest(http.MethodGet, "/api/v1/node/policy", nil)
	deletedPolicyRequest.Header.Set("Authorization", "Bearer "+communicationKey)
	deletedPolicyRequest.Header.Set("X-OpenPPP2-Node-ID", nodeResult.Key)
	deletedPolicy := httptest.NewRecorder()
	handler.ServeHTTP(deletedPolicy, deletedPolicyRequest)
	if deletedPolicy.Code != http.StatusUnauthorized {
		t.Fatalf("deleted node ID still works: %d %s", deletedPolicy.Code, deletedPolicy.Body.String())
	}
}

func performJSON(t *testing.T, handler http.Handler, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func performJSONWithCookie(t *testing.T, handler http.Handler, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeRecorder(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), target); err != nil {
		t.Fatalf("decode response: %v: %s", err, recorder.Body.String())
	}
}

func uintString(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = digits[value%10]
		value /= 10
	}
	return string(buffer[index:])
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
