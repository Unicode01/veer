package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const apiServerShutdownTimeout = 15 * time.Second

func computeBinaryHash() string {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("compute binary hash: get executable: %v", err)
		return ""
	}
	f, err := os.Open(exe)
	if err != nil {
		log.Printf("compute binary hash: open executable: %v", err)
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Printf("compute binary hash: read executable: %v", err)
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Main(buildNonce string) {
	workerMode := flag.Bool("worker", false, "run in worker mode")
	rangeWorkerMode := flag.Bool("range-worker", false, "run in range worker mode")
	sharedProxyMode := flag.Bool("shared-proxy", false, "run as shared proxy")
	workerIndex := flag.Int("id", 0, "worker slot index")
	sockPath := flag.String("sock", "", "unix socket path")
	configPath := flag.String("config", "config.json", "config file path")
	flag.Parse()

	if *workerMode {
		if *sockPath == "" {
			log.Fatal("worker mode requires --sock")
		}
		runWorker(*workerIndex, *sockPath)
		return
	}

	if *rangeWorkerMode {
		if *sockPath == "" {
			log.Fatal("range-worker mode requires --sock")
		}
		runRangeWorker(*workerIndex, *sockPath)
		return
	}

	if *sharedProxyMode {
		if *sockPath == "" {
			log.Fatal("shared-proxy mode requires --sock")
		}
		runSharedProxy(*sockPath)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if features := cfg.EnabledExperimentalFeatures(); len(features) > 0 {
		log.Printf("experimental features enabled: %s", strings.Join(features, ", "))
	}

	db, err := initDB("forward.db")
	if err != nil {
		log.Fatalf("init db: %v", err)
	}
	defer db.Close()

	binHash := computeBinaryHash()
	log.Printf("binary hash: %s", binHash)

	pm, err := newProcessManager(db, cfg, binHash)
	if err != nil {
		log.Fatalf("init process manager: %v", err)
	}

	pm.redistributeWorkers()
	pm.startAccepting()
	pm.setReady(true)

	apiServer := startAPI(cfg, db, pm)

	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	<-sigCtx.Done()

	log.Println("shutting down...")
	pm.setReady(false)
	if apiServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), apiServerShutdownTimeout)
		if err := apiServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("http server shutdown: %v", err)
			_ = apiServer.Close()
		}
		cancel()
	}
	pm.stopAll()
}
