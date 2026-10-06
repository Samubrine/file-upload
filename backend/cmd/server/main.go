package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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

	rootKeyHex := os.Getenv("CRYPTO_ROOT_KEY_" + activeKeyID)
	var rootKey []byte
	if rootKeyHex != "" {
		var err error
		rootKey, err = hex.DecodeString(rootKeyHex)
		if err != nil || len(rootKey) != 32 {
			log.Fatalf("Invalid CRYPTO_ROOT_KEY_%s: must be 32 bytes hex", activeKeyID)
		}
	} else {
		// Dev default fallback: generate 32 bytes or deterministic dev key
		rootKey = []byte("ciphervault_dev_root_key_32_bytes!!")
		log.Printf("NOTICE: Using default 32-byte development root key for id %s", activeKeyID)
	}

	indexKeyHex := os.Getenv("IDENTITY_INDEX_KEY")
	var indexKey []byte
	if indexKeyHex != "" {
		var err error
		indexKey, err = hex.DecodeString(indexKeyHex)
		if err != nil || len(indexKey) != 32 {
			log.Fatalf("Invalid IDENTITY_INDEX_KEY: must be 32 bytes hex")
		}
	} else {
		indexKey = []byte("ciphervault_dev_index_key_32_byt!")
		log.Printf("NOTICE: Using default 32-byte development identity index key")
	}

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

