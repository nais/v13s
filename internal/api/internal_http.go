package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"riverqueue.com/riverui"
)

type Handler struct {
	Path    string
	Handler http.Handler
}

func runInternalHTTPServer(ctx context.Context, listenAddress string, reg prometheus.Gatherer, log logrus.FieldLogger, extraHandlers ...Handler) error {
	router := chi.NewRouter()
	router.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	router.Get("/healthz", func(_ http.ResponseWriter, _ *http.Request) {})

	router.HandleFunc("/pprof/*", pprof.Index)
	router.HandleFunc("/pprof/profile", pprof.Profile)
	router.HandleFunc("/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/pprof/trace", pprof.Trace)

	router.Handle("/pprof/goroutine", pprof.Handler("goroutine"))
	router.Handle("/pprof/threadcreate", pprof.Handler("threadcreate"))
	router.Handle("/pprof/mutex", pprof.Handler("mutex"))
	router.Handle("/pprof/heap", pprof.Handler("heap"))
	router.Handle("/pprof/block", pprof.Handler("block"))
	router.Handle("/pprof/allocs", pprof.Handler("allocs"))

	for _, handler := range extraHandlers {
		if handler.Handler == nil {
			log.Errorf("Handler for %s is nil", handler.Path)
			continue
		}
		router.Mount(handler.Path, handler.Handler)
	}

	srv := &http.Server{
		Addr:              listenAddress,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	wg, ctx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		log.Infof("Internal HTTP server shutting down...")
		if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.WithError(err).Infof("HTTP server shutdown failed")
			return err
		}
		return nil
	})

	wg.Go(func() error {
		log.Infof("Internal HTTP server accepting requests on %q", listenAddress)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Infof("unexpected error from HTTP server")
			return err
		}
		log.Infof("Internal HTTP server finished, terminating...")
		return nil
	})
	return wg.Wait()
}

func riverUI(ctx context.Context, dbUrl string) *riverui.Server {
	pool, err := pgxpool.New(ctx, dbUrl)
	if err != nil {
		logrus.Errorf("%v", err)
		return nil
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	riverClient, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Logger: logger,
	})
	if err != nil {
		logrus.Errorf("%v", err)
		return nil
	}

	opts := &riverui.ServerOpts{
		Client: riverClient,
		DB:     pool,
		Logger: logger,
		Prefix: "/riverui", // mount the UI and its APIs under /riverui
	}
	server, err := riverui.NewServer(opts)
	if err != nil {
		logrus.Errorf("%v", err)
		return nil
	}
	// Start the server to initialize background processes for caching and periodic queries:
	if err := server.Start(ctx); err != nil {
		logrus.Errorf("river UI server failed to start: %v", err)
	}
	return server
}
