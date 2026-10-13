package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ciphervault/internal/crypto"
	"ciphervault/internal/files"
	"ciphervault/internal/httpapi"
	"ciphervault/internal/sharing"
	"ciphervault/internal/storage"
	"ciphervault/internal/users"
)

func main() {
	port := flag.Int("port", 8080, "HTTP server port")
	dbPath := flag.String("db", "data/ciphervault.db", "SQLite database file path")
	staticDir := flag.String("static", "frontend/dist", "Path to static frontend dist directory")
	benchmarkMode := flag.Bool("benchmark", false, "Enable Server-Timing metrics on download")
	flag.Parse()

	log.Printf("Starting CipherVault server on port %d...", *port)

	// Configure root encryption keys
	activeKeyID := os.Getenv("ACTIVE_ROOT_KEY_ID")
	if activeKeyID == "" {
		activeKeyID = "root-1"
	}

	rootKeyEnv := os.Getenv("CRYPTO_ROOT_KEY_" + activeKeyID)
	rootKey := normalizeKey32(rootKeyEnv, "ciphervault_dev_root_key_32_byte")
	log.Printf("Loaded 32-byte root key for active id: %s", activeKeyID)

	indexKeyEnv := os.Getenv("IDENTITY_INDEX_KEY")
	indexKey := normalizeKey32(indexKeyEnv, "ciphervault_dev_index_key_32_byt")
	log.Printf("Loaded 32-byte identity index key")

	kp := crypto.NewMemoryKeyProvider(map[string][]byte{
		activeKeyID: rootKey,
	})

	// Open database
	db, err := storage.OpenDB(*dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	log.Printf("Connected to database at %s (WAL mode, foreign keys active)", *dbPath)

	// Services
	usersService := users.NewService(db, kp, activeKeyID, indexKey)
	filesService := files.NewService(db, kp, activeKeyID)
	sharingService := sharing.NewService(db, indexKey)

	// Check if frontend directory exists
	actualStaticDir := *staticDir
	if _, err := os.Stat(actualStaticDir); os.IsNotExist(err) {
		log.Printf("Static frontend dir %s does not exist yet; API mode only", actualStaticDir)
		actualStaticDir = ""
	}

	server := httpapi.NewServer(httpapi.ServerConfig{
		DB:             db,
		UsersService:   usersService,
		FilesService:   filesService,
		SharingService: sharingService,
		CookieName:     "ciphervault_session",
		SecureCookies:  false, // dev default
		BenchmarkMode:  *benchmarkMode,
		StaticDir:      actualStaticDir,
	})

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      server,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("CipherVault listening on http://localhost:%d", *port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("Server stopped")
}

func normalizeKey32(raw string, defaultVal string) []byte {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultVal
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b
	}
	if len(raw) == 32 {
		return []byte(raw)
	}
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

