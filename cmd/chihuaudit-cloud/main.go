package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"chihuaudit/cloud/alerting"
	"chihuaudit/cloud/handlers"
	"chihuaudit/cloud/middleware"
	"chihuaudit/cloud/models"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

//go:embed static/*
var staticFS embed.FS

func main() {
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./chihuaudit-cloud.db"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}
	middleware.SetJWTSecret(jwtSecret)

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8091"
	}

	if err := models.InitDB(dbPath); err != nil {
		log.Fatalf("database init: %v", err)
	}

	// Apply all migrations in order
	for _, mf := range []string{
		"migrations/001_init.sql",
		"migrations/002_host_config.sql",
		"migrations/003_security_and_alerts.sql",
		"migrations/004_fix_audits_cascade.sql",
		"migrations/005_alerts_table.sql",
	} {
		migrationSQL, err := migrationsFS.ReadFile(mf)
		if err != nil {
			log.Fatalf("read migration %s: %v", mf, err)
		}
		if err := models.RunMigrations(migrationSQL); err != nil {
			log.Fatalf("run migration %s: %v", mf, err)
		}
	}

	// Background goroutines
	go runPersistentAlertChecker()
	go runAuditCleanup()

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/setup", handlers.HandleSetup)
	mux.HandleFunc("/api/login", handlers.HandleLogin)
	mux.HandleFunc("/api/logout", handlers.HandleLogout)
	mux.HandleFunc("/api/audits", handlers.HandlePushAudit)
	mux.HandleFunc("/api/dashboard", middleware.RequireJWT(handlers.HandleDashboard))
	mux.HandleFunc("/api/users", middleware.RequireJWT(handlers.HandleCreateUser))
	mux.HandleFunc("/api/me", middleware.RequireJWT(handlers.HandleMe))

	// Host routes
	mux.HandleFunc("/api/hosts", middleware.RequireJWT(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handlers.HandleCreateHost(w, r)
		} else {
			handlers.HandleListHosts(w, r)
		}
	}))
	mux.HandleFunc("/api/alerts/recent", middleware.RequireJWT(handlers.HandleRecentAlerts))
	mux.HandleFunc("/api/hosts/", middleware.RequireJWT(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/hosts/")
		switch {
		case strings.HasSuffix(path, "/audits"):
			handlers.HandleListAudits(w, r)
		case strings.HasSuffix(path, "/config"):
			if r.Method == http.MethodPut {
				handlers.HandleUpdateHostConfig(w, r)
			} else {
				handlers.HandleGetHostConfig(w, r)
			}
		case strings.HasSuffix(path, "/rotate-key"):
			handlers.HandleRotateAPIKey(w, r)
		case strings.HasSuffix(path, "/test-webhook"):
			handlers.HandleTestWebhook(w, r)
		case strings.HasSuffix(path, "/metrics"):
			handlers.HandleHostMetrics(w, r)
		case strings.HasSuffix(path, "/alerts"):
			handlers.HandleHostAlerts(w, r)
		case strings.HasSuffix(path, "/audit-keys"):
			handlers.HandleHostAuditKeys(w, r)
		case r.Method == http.MethodDelete:
			handlers.HandleDeleteHost(w, r)
		default:
			handlers.HandleGetHost(w, r)
		}
	}))

	// Static files
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static fs: %v", err)
	}
	fileServer := http.FileServer(http.FS(staticSub))
	mux.Handle("/", fileServer)

	log.Printf("Listening on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, middleware.SecurityHeaders(mux)); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func runPersistentAlertChecker() {
	checkPersistentAlerts()
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		checkPersistentAlerts()
	}
}

func checkPersistentAlerts() {
	alerts, err := models.GetPendingPersistentAlerts(48 * time.Hour)
	if err != nil {
		log.Printf("persistent alerts check error: %v", err)
		return
	}

	for _, a := range alerts {
		if a.WebhookURL != "" {
			if err := alerting.SendPersistentAlertWebhook(
				a.WebhookURL, a.HostName, a.Metric,
				a.ThresholdValue, a.CurrentValue, a.FirstExceededAt,
			); err != nil {
				log.Printf("persistent alert webhook error for host %q: %v", a.HostName, err)
				continue
			}
		}
		if err := models.MarkPersistentAlerted(a.ID); err != nil {
			log.Printf("mark persistent alerted error: %v", err)
		}
	}

	if len(alerts) > 0 {
		log.Printf("persistent alerts: processed %d alerts", len(alerts))
	}
}

func runAuditCleanup() {
	models.CleanupOldAudits()
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		models.CleanupOldAudits()
	}
}
