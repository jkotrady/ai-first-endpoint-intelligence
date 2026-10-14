package main

import (
	"aiforensics.local/platform/internal/console"
	"aiforensics.local/platform/internal/pilot"
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	dir := flag.String("state", "work/pilot", "Private pilot state directory")
	initUser := flag.String("init", "", "Initialize NEW state directory for username, then exit")
	demo := flag.Bool("demo", false, "Run historical synthetic demo without real agents")
	flag.Parse()
	if *initUser != "" {
		if e := pilot.Init(*dir, *initUser); e != nil {
			log.Fatal(e)
		}
		log.Printf("Initialized. Credentials: %s (owner-only); values omitted", filepath.Join(*dir, "first-login.txt"))
		return
	}
	var handler http.Handler
	var agent http.Handler
	if *demo {
		handler = console.New().Handler()
	} else {
		app, e := pilot.Open(*dir)
		if e != nil {
			log.Fatalf("Open pilot: %v; initialize a new directory with --init USER", e)
		}
		handler = app.Handler()
		agent = app.AgentHandler()
	}
	mk := func(addr string, h http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	}
	ui := mk("127.0.0.1:8080", handler)
	ui.WriteTimeout = 60 * time.Second // AI provider requests have a separate 45-second deadline.
	servers := []*http.Server{ui}
	errs := make(chan error, 2)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { errs <- ui.ListenAndServe() }()
	if agent != nil {
		s := mk("127.0.0.1:8443", agent)
		s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		servers = append(servers, s)
		go func() {
			errs <- s.ListenAndServeTLS(filepath.Join(*dir, "server.pem"), filepath.Join(*dir, "server.key"))
		}()
	}
	log.Print("Local console: http://127.0.0.1:8080 ; agent TLS gateway: 127.0.0.1:8443 ; internal pilot, not public deployment")
	select {
	case <-ctx.Done():
	case e := <-errs:
		if e != http.ErrServerClosed {
			log.Print(e)
		}
	}
	end, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(end)
	}
}
