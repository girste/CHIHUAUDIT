package handlers

import (
	"chihuaudit/cloud/models"
	"encoding/json"
	"log"
	"net/http"
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
