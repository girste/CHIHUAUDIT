package handlers

import (
	"chihuaudit/cloud/models"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type dashboardStats struct {
	TotalHosts  int `json:"total_hosts"`
	TotalAudits int `json:"total_audits"`
	OnlineHosts int `json:"online_hosts"`
}

func HandleDashboard(w http.ResponseWriter, r *http.Request) {
	var stats dashboardStats

	err := models.DB.QueryRow("SELECT count(*) FROM hosts").Scan(&stats.TotalHosts)
	if err != nil {
		log.Printf("dashboard hosts count error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	err = models.DB.QueryRow("SELECT count(*) FROM audits").Scan(&stats.TotalAudits)
	if err != nil {
		log.Printf("dashboard audits count error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Hosts seen in the last 24 hours
	err = models.DB.QueryRow("SELECT count(*) FROM hosts WHERE last_seen > datetime('now', '-24 hours')").Scan(&stats.OnlineHosts)
	if err != nil {
		log.Printf("dashboard online count error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func HandleRecentAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := models.GetRecentAlerts(20)
	if err != nil {
		log.Printf("recent alerts error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []models.RecentAlert{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func HandleHostAlerts(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hosts/")
	parts := strings.SplitN(path, "/", 2)
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}
	alerts, err := models.GetHostAlerts(id)
	if err != nil {
		log.Printf("host alerts error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []models.RecentAlert{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func HandleHostMetrics(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hosts/")
	parts := strings.SplitN(path, "/", 2)
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}
	metrics, err := models.GetHostMetrics(id, 30)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		}
		log.Printf("host metrics error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if metrics == nil {
		metrics = []models.MetricPoint{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func HandleHostAuditKeys(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hosts/")
	parts := strings.SplitN(path, "/", 2)
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}
	keys, err := models.GetLatestAuditKeys(id)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		}
		log.Printf("host audit keys error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}
