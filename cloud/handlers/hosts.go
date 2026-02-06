package handlers

import (
	"chihuaudit/cloud/alerting"
	"chihuaudit/cloud/models"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type createHostRequest struct {
	Name string `json:"name"`
}

func HandleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := models.ListHosts()
	if err != nil {
		log.Printf("list hosts error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []models.HostWithLastAudit{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

func HandleGetHost(w http.ResponseWriter, r *http.Request) {
	id, err := extractHostID(r.URL.Path)
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}

	host, err := models.GetHost(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"host not found"}`, http.StatusNotFound)
			return
		}
		log.Printf("get host error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(host)
}

func HandleCreateHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req createHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}

	apiKey := GenerateAPIKey()
	host, err := models.CreateHost(req.Name, apiKey)
	if err != nil {
		log.Printf("create host error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	resp := struct {
		models.Host
		APIKey string `json:"api_key"`
	}{Host: *host, APIKey: apiKey}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func HandleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := extractHostID(r.URL.Path)
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}

	rows, err := models.DeleteHost(id)
	if err != nil {
		log.Printf("delete host error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if rows == 0 {
		http.Error(w, `{"error":"host not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func HandleGetHostConfig(w http.ResponseWriter, r *http.Request) {
	id, err := extractHostID(r.URL.Path)
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}

	cfg, err := models.GetHostConfig(id)
	if err != nil {
		log.Printf("get host config error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func HandleUpdateHostConfig(w http.ResponseWriter, r *http.Request) {
	id, err := extractHostID(r.URL.Path)
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}

	var cfg models.HostConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	cfg.HostID = id

	if err := models.UpdateHostConfig(&cfg); err != nil {
		log.Printf("update host config error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func HandleRotateAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	id, err := extractHostID(r.URL.Path)
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}

	newKey := GenerateAPIKey()
	newHash := models.HashAPIKey(newKey)

	if err := models.RotateHostAPIKey(id, newHash); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"host not found"}`, http.StatusNotFound)
			return
		}
		log.Printf("rotate api key error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"api_key": newKey})
}

func HandleTestWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	id, err := extractHostID(r.URL.Path)
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}

	host, err := models.GetHost(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"host not found"}`, http.StatusNotFound)
			return
		}
		log.Printf("test webhook get host error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	cfg, err := models.GetHostConfig(id)
	if err != nil {
		log.Printf("test webhook get config error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if cfg.WebhookURL == "" {
		http.Error(w, `{"error":"no webhook URL configured"}`, http.StatusBadRequest)
		return
	}

	if err := alerting.SendTestWebhook(cfg.WebhookURL, host.Name); err != nil {
		log.Printf("test webhook error: %v", err)
		http.Error(w, `{"error":"webhook failed: `+err.Error()+`"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func extractHostID(path string) (int, error) {
	path = strings.TrimPrefix(path, "/api/hosts/")
	parts := strings.SplitN(path, "/", 2)
	return strconv.Atoi(parts[0])
}
