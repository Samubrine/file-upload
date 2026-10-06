package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"ciphervault/internal/crypto"
	"ciphervault/internal/files"
	"ciphervault/internal/httpapi"
	"ciphervault/internal/sharing"
	"ciphervault/internal/storage"
	"ciphervault/internal/users"
)

type Fixture struct {
	ID        string
	Filename  string
	Category  string
	Data      []byte
	SHA256Hex string
}

type Measurement struct {
	RunID            string
	FixtureID        string
	VariantID        string
	Iteration        int
	Warmup           bool
	PlaintextBytes   int64
	CiphertextBytes  int64
	EnvelopeBytes    int64
	EncryptCipherNs  int64
	SealTotalNs      int64
	DBReadNs         int64
	KDFNs            int64
	MACVerifyNs      int64
	DecryptCipherNs  int64
	OpenTotalNs      int64
	ClientDownloadNs int64
	ChecksumOK       bool
	HTTPStatus       int
	ErrorCode        string
	EnvironmentID    string
}

type SummaryRow struct {
	FixtureID              string  `json:"fixture_id"`
	VariantID              string  `json:"variant_id"`
	N                      int     `json:"n"`
	Successes              int     `json:"successes"`
	Failures               int     `json:"failures"`
	PlaintextBytes         int64   `json:"plaintext_bytes"`
	CiphertextBytes        int64   `json:"ciphertext_bytes"`
	EnvelopeBytes          int64   `json:"envelope_bytes"`
	SealMedianNs           int64   `json:"seal_median_ns"`
	SealP95Ns              int64   `json:"seal_p95_ns"`
	DecryptMedianNs        int64   `json:"decrypt_median_ns"`
	DecryptP95Ns           int64   `json:"decrypt_p95_ns"`
	ClientDownloadMedianNs int64   `json:"client_download_median_ns"`
	ClientDownloadP95Ns    int64   `json:"client_download_p95_ns"`
	ThroughputMiBs         float64 `json:"throughput_mib_s"`
}

func generateFixtures() []Fixture {
	fixtures := []Fixture{
		// 1. Small text PDF document fixture
		makeFixture("small-pdf", "small_notes.pdf", "document", append([]byte("%PDF-1.4 text notes"), bytes.Repeat([]byte("A"), 512)...)),

		// 2. Mock ID card PNG
		makeFixture("mock-id-png", "mock_id.png", "id_card", append([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0xAA}, 4096)...)),

		// 3. Sample PDF document
		makeFixture("sample-pdf", "sample.pdf", "document", append([]byte("%PDF-1.4 sample encrypted educational pdf"), bytes.Repeat([]byte{0xBB}, 16384)...)),

		// 4. Sample DOCX document (PK ZIP)
		makeFixture("sample-docx", "sample.docx", "document", append([]byte{0x50, 0x4B, 0x03, 0x04}, bytes.Repeat([]byte{0xCC}, 8192)...)),

		// 5. Sample MP4 video
		makeFixture("sample-mp4", "sample.mp4", "video", append([]byte{0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'}, bytes.Repeat([]byte{0xDD}, 32768)...)),

		// 6. 1 KiB binary
		makeBinaryFixture("binary-1kib", "data_1kib.png", 1024),

		// 7. 64 KiB binary
		makeBinaryFixture("binary-64kib", "data_64kib.png", 64*1024),

		// 8. 1 MiB binary
		makeBinaryFixture("binary-1mib", "data_1mib.png", 1024*1024),
	}
	return fixtures
}

func makeFixture(id, filename, category string, data []byte) Fixture {
	h := sha256.Sum256(data)
	return Fixture{
		ID:        id,
		Filename:  filename,
		Category:  category,
		Data:      data,
		SHA256Hex: hex.EncodeToString(h[:]),
	}
}

func makeBinaryFixture(id, filename string, size int) Fixture {
	data := make([]byte, size)
	// Start with PNG magic bytes so it passes image file validation
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	copy(data, pngMagic)
	_, _ = io.ReadFull(rand.Reader, data[len(pngMagic):])
	h := sha256.Sum256(data)
	return Fixture{
		ID:        id,
		Filename:  filename,
		Category:  "image",
		Data:      data,
		SHA256Hex: hex.EncodeToString(h[:]),
	}
}

func parseServerTiming(header string) (dbNs, kdfNs, macNs, decryptNs, totalNs int64) {
	if header == "" {
		return
	}
	parts := strings.Split(header, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		kv := strings.Split(p, ";")
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		durStr := strings.TrimPrefix(strings.TrimSpace(kv[1]), "dur=")
		durMs, err := strconv.ParseFloat(durStr, 64)
		if err != nil {
			continue
		}
		ns := int64(durMs * 1_000_000)
		switch name {
		case "db":
			dbNs = ns
		case "kdf":
			kdfNs = ns
		case "mac":
			macNs = ns
		case "decrypt":
			decryptNs = ns
		case "total":
			totalNs = ns
		}
	}
	return
}

func main() {
	log.Println("Starting CipherVault reproducible benchmark protocol...")

	outDir := filepath.Join("benchmarks", "results")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("Failed to create results dir: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "ciphervault_bench_*")
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "bench.db")
	db, err := storage.OpenDB(dbPath)
	if err != nil {
		log.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	rootKeyID := "bench-root"
	rootKey := bytes.Repeat([]byte{0x77}, 32)
	indexKey := bytes.Repeat([]byte{0x88}, 32)

	kp := crypto.NewMemoryKeyProvider(map[string][]byte{rootKeyID: rootKey})
	uSvc := users.NewService(db, kp, rootKeyID, indexKey)
	fSvc := files.NewService(db, kp, rootKeyID)
	sSvc := sharing.NewService(db, indexKey)

	server := httpapi.NewServer(httpapi.ServerConfig{
		DB:             db,
		UsersService:   uSvc,
		FilesService:   fSvc,
		SharingService: sSvc,
		CookieName:     "ciphervault_session",
		SecureCookies:  false,
		BenchmarkMode:  true,
	})

	ts := httptest.NewServer(server)
	defer ts.Close()

	// 1. Record environment
	envID := fmt.Sprintf("%s-%s-%s", runtime.GOOS, runtime.GOARCH, time.Now().Format("20060102150405"))
	envData := map[string]interface{}{
		"environment_id": envID,
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"cpus":           runtime.NumCPU(),
		"go_version":     runtime.Version(),
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"notes":          "Standard single-process local execution, monotonic timing",
	}
	envJSON, _ := json.MarshalIndent(envData, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "environment.json"), envJSON, 0644)

	// 2. Register benchmark user
	client := ts.Client()
	regBody, _ := json.Marshal(users.RegisterInput{
		FullName:           "Benchmark Runner",
		Username:           "bench_runner",
		Email:              "bench@example.edu",
		Password:           "BenchmarkPassword123!",
		NoticeVersion:      "1.0",
		NoticeAcknowledged: true,
	})
	regResp, err := client.Post(ts.URL+"/auth/register", "application/json", bytes.NewReader(regBody))
	if err != nil || regResp.StatusCode != http.StatusCreated {
		log.Fatalf("Failed to register benchmark user: %v", err)
	}

	var sessionResp httpapi.SessionResponse
	_ = json.NewDecoder(regResp.Body).Decode(&sessionResp)
	regResp.Body.Close()

	var sessionCookie *http.Cookie
	for _, c := range regResp.Cookies() {
		if c.Name == "ciphervault_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		log.Fatal("Session cookie missing")
	}

	// 3. Upload fixtures and upload envelope sizes
	fixtures := generateFixtures()
	uploadedFiles := make(map[string]*files.OwnerFileDTO)

	for _, fix := range fixtures {
		buf := new(bytes.Buffer)
		mw := multipart.NewWriter(buf)
		part, err := mw.CreateFormFile("file", fix.Filename)
		if err != nil {
			log.Fatal(err)
		}
		_, _ = part.Write(fix.Data)
		if fix.Category != "" {
			_ = mw.WriteField("category", fix.Category)
		}
		_ = mw.Close()

		req, _ := http.NewRequest("POST", ts.URL+"/files", buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-CSRF-Token", sessionResp.CSRFToken)
		req.AddCookie(sessionCookie)

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusCreated {
			log.Fatalf("Failed to upload fixture %s: status %d", fix.ID, resp.StatusCode)
		}

		var ownerFile files.OwnerFileDTO
		_ = json.NewDecoder(resp.Body).Decode(&ownerFile)
		resp.Body.Close()

		uploadedFiles[fix.ID] = &ownerFile
		log.Printf("Uploaded fixture %s (file_id: %s, %d bytes)", fix.ID, ownerFile.ID, len(fix.Data))
	}

	// 4. Measure pure crypto seal overhead across variants and run HTTP download benchmarks
	var measurements []Measurement
	runCounter := 0

	rawCSVFile, err := os.Create(filepath.Join(outDir, "raw.csv"))
	if err != nil {
		log.Fatal(err)
	}
	defer rawCSVFile.Close()

	csvWriter := csv.NewWriter(rawCSVFile)
	_ = csvWriter.Write([]string{
		"run_id", "fixture_id", "variant_id", "iteration", "warmup",
		"plaintext_bytes", "ciphertext_bytes", "envelope_bytes",
		"encrypt_cipher_ns", "seal_total_ns", "db_read_ns", "kdf_ns",
		"mac_verify_ns", "decrypt_cipher_ns", "open_total_ns",
		"client_download_ns", "checksum_ok", "http_status", "error_code", "environment_id",
	})

	for _, fix := range fixtures {
		fileDTO := uploadedFiles[fix.ID]

		for _, variantID := range crypto.AllVariantIDs {
			// Measure standalone pure cipher seal on fixture data
			spec, _ := crypto.GetVariant(variantID)
			ctx := crypto.Context{
				PayloadID:       "bench-p",
				OwnerID:         "bench-o",
				FileID:          &fileDTO.ID,
				ContentRevision: 1,
				VariantID:       variantID,
			}
			envBytes, sealTimings, err := crypto.Seal(ctx, rootKeyID, rootKey, fix.Data)
			if err != nil {
				log.Fatalf("Seal failed for %s: %v", variantID, err)
			}
			envelopeLen := int64(len(envBytes))

			// Calculate exact ciphertext bytes
			headerLen := int(envBytes[5])<<24 | int(envBytes[6])<<16 | int(envBytes[7])<<8 | int(envBytes[8])
			ciphertextLen := envelopeLen - int64(9+headerLen+32)

			// 5 warmups, then 30 measured runs
			totalRuns := 5 + 30
			for iter := 1; iter <= totalRuns; iter++ {
				runCounter++
				runID := fmt.Sprintf("run-%05d", runCounter)
				isWarmup := iter <= 5

				dlURL := fmt.Sprintf("%s/files/%s/download?variant=%s", ts.URL, fileDTO.ID, variantID)
				req, _ := http.NewRequest("GET", dlURL, nil)
				req.AddCookie(sessionCookie)
				req.Header.Set("Cache-Control", "no-store")

				startDownload := time.Now()
				resp, err := client.Do(req)
				var downloadNs int64
				var status int
				var bodyBytes []byte

				if err == nil {
					bodyBytes, _ = io.ReadAll(resp.Body)
					resp.Body.Close()
					downloadNs = time.Since(startDownload).Nanoseconds()
					status = resp.StatusCode
				} else {
					downloadNs = time.Since(startDownload).Nanoseconds()
					status = 0
				}

				dlHash := sha256.Sum256(bodyBytes)
				dlHex := hex.EncodeToString(dlHash[:])
				checksumOK := (dlHex == fix.SHA256Hex && status == http.StatusOK)

				dbNs, kdfNs, macNs, decNs, totalNs := parseServerTiming(resp.Header.Get("Server-Timing"))

				m := Measurement{
					RunID:            runID,
					FixtureID:        fix.ID,
					VariantID:        variantID,
					Iteration:        iter,
					Warmup:           isWarmup,
					PlaintextBytes:   int64(len(fix.Data)),
					CiphertextBytes:  ciphertextLen,
					EnvelopeBytes:    envelopeLen,
					EncryptCipherNs:  sealTimings.EncryptCipherDuration.Nanoseconds(),
					SealTotalNs:      sealTimings.SealTotalDuration.Nanoseconds(),
					DBReadNs:         dbNs,
					KDFNs:            kdfNs,
					MACVerifyNs:      macNs,
					DecryptCipherNs:  decNs,
					OpenTotalNs:      totalNs,
					ClientDownloadNs: downloadNs,
					ChecksumOK:       checksumOK,
					HTTPStatus:       status,
					ErrorCode:        "",
					EnvironmentID:    envID,
				}

				measurements = append(measurements, m)

				_ = csvWriter.Write([]string{
					m.RunID, m.FixtureID, m.VariantID, strconv.Itoa(m.Iteration), strconv.FormatBool(m.Warmup),
					strconv.FormatInt(m.PlaintextBytes, 10), strconv.FormatInt(m.CiphertextBytes, 10), strconv.FormatInt(m.EnvelopeBytes, 10),
					strconv.FormatInt(m.EncryptCipherNs, 10), strconv.FormatInt(m.SealTotalNs, 10),
					strconv.FormatInt(m.DBReadNs, 10), strconv.FormatInt(m.KDFNs, 10),
					strconv.FormatInt(m.MACVerifyNs, 10), strconv.FormatInt(m.DecryptCipherNs, 10), strconv.FormatInt(m.OpenTotalNs, 10),
					strconv.FormatInt(m.ClientDownloadNs, 10), strconv.FormatBool(m.ChecksumOK),
					strconv.Itoa(m.HTTPStatus), m.ErrorCode, m.EnvironmentID,
				})
			}
			_ = spec
		}
		log.Printf("Completed benchmarks for fixture %s across all 14 variants", fix.ID)
	}

	csvWriter.Flush()

	// 5. Compute summary statistics (ignoring warmups)
	type key struct {
		fixtureID string
		variantID string
	}
	grouped := make(map[key][]Measurement)
	for _, m := range measurements {
		if !m.Warmup {
			k := key{m.FixtureID, m.VariantID}
			grouped[k] = append(grouped[k], m)
		}
	}

	var summaryRows []SummaryRow
	for k, list := range grouped {
		n := len(list)
		successes := 0
		failures := 0

		var sealTimes []int64
		var decTimes []int64
		var dlTimes []int64

		for _, m := range list {
			if m.ChecksumOK {
				successes++
			} else {
				failures++
			}
			sealTimes = append(sealTimes, m.SealTotalNs)
			decTimes = append(decTimes, m.DecryptCipherNs)
			dlTimes = append(dlTimes, m.ClientDownloadNs)
		}

		sort.Slice(sealTimes, func(i, j int) bool { return sealTimes[i] < sealTimes[i] })
		sort.Slice(decTimes, func(i, j int) bool { return decTimes[i] < decTimes[i] })
		sort.Slice(dlTimes, func(i, j int) bool { return dlTimes[i] < dlTimes[i] })

		p95Idx := int(math.Ceil(0.95*float64(n))) - 1
		if p95Idx >= n {
			p95Idx = n - 1
		}
		if p95Idx < 0 {
			p95Idx = 0
		}

		medianIdx := n / 2

		ptBytes := list[0].PlaintextBytes
		dlMedian := dlTimes[medianIdx]
		var throughput float64
		if dlMedian > 0 {
			throughput = (float64(ptBytes) / (1024 * 1024)) / (float64(dlMedian) / 1e9)
		}

		summaryRows = append(summaryRows, SummaryRow{
			FixtureID:              k.fixtureID,
			VariantID:              k.variantID,
			N:                      n,
			Successes:              successes,
			Failures:               failures,
			PlaintextBytes:         ptBytes,
			CiphertextBytes:        list[0].CiphertextBytes,
			EnvelopeBytes:          list[0].EnvelopeBytes,
			SealMedianNs:           sealTimes[medianIdx],
			SealP95Ns:              sealTimes[p95Idx],
			DecryptMedianNs:        decTimes[medianIdx],
			DecryptP95Ns:           decTimes[p95Idx],
			ClientDownloadMedianNs: dlTimes[medianIdx],
			ClientDownloadP95Ns:    dlTimes[p95Idx],
			ThroughputMiBs:         throughput,
		})
	}

	// Sort summary rows consistently
	sort.Slice(summaryRows, func(i, j int) bool {
		if summaryRows[i].FixtureID != summaryRows[j].FixtureID {
			return summaryRows[i].FixtureID < summaryRows[j].FixtureID
		}
		return summaryRows[i].VariantID < summaryRows[j].VariantID
	})

	// Write summary.csv
	sumCSVFile, err := os.Create(filepath.Join(outDir, "summary.csv"))
	if err != nil {
		log.Fatal(err)
	}
	defer sumCSVFile.Close()

	sumWriter := csv.NewWriter(sumCSVFile)
	_ = sumWriter.Write([]string{
		"fixture_id", "variant_id", "n", "successes", "failures",
		"plaintext_bytes", "ciphertext_bytes", "envelope_bytes",
		"seal_median_ns", "seal_p95_ns", "decrypt_median_ns", "decrypt_p95_ns",
		"client_download_median_ns", "client_download_p95_ns", "throughput_mib_s",
	})

	for _, s := range summaryRows {
		_ = sumWriter.Write([]string{
			s.FixtureID, s.VariantID, strconv.Itoa(s.N), strconv.Itoa(s.Successes), strconv.Itoa(s.Failures),
			strconv.FormatInt(s.PlaintextBytes, 10), strconv.FormatInt(s.CiphertextBytes, 10), strconv.FormatInt(s.EnvelopeBytes, 10),
			strconv.FormatInt(s.SealMedianNs, 10), strconv.FormatInt(s.SealP95Ns, 10),
			strconv.FormatInt(s.DecryptMedianNs, 10), strconv.FormatInt(s.DecryptP95Ns, 10),
			strconv.FormatInt(s.ClientDownloadMedianNs, 10), strconv.FormatInt(s.ClientDownloadP95Ns, 10),
			fmt.Sprintf("%.3f", s.ThroughputMiBs),
		})
	}
	sumWriter.Flush()

	// Write summary.json
	sumJSON, _ := json.MarshalIndent(summaryRows, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "summary.json"), sumJSON, 0644)

	log.Printf("Benchmark run complete! Results written to %s", outDir)
}

