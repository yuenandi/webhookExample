package main

import (
	"crypto/tls"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/webhookExample/k8s"
	"github.com/webhookExample/options"
	"github.com/webhookExample/webhook"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	parameters := options.Parameters
	if parameters.AutoAuthentication {
		if err := k8s.NewK8s(&parameters).Run(); err != nil {
			log.Panic(err)
		}
	}
	pair, err := tls.LoadX509KeyPair(parameters.CertFile, parameters.KeyFile)
	if err != nil {
		log.Errorf("Failed to load key pair: %v", err)
	}

	whsvr := &webhook.WebhookServer{
		Server: &http.Server{
			Addr:      fmt.Sprintf(":%v", parameters.Port),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
		},
	}

	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc(options.MutatePath, whsvr.Serve)
	whsvr.Server.Handler = mux

	// start webhook server in new routine
	go func() {
		if err := whsvr.Server.ListenAndServeTLS("", ""); err != nil {
			log.Errorf("Failed to listen and serve webhook server: %v", err)
		}
	}()

	log.Infof("Server started, Listening to the port %d", parameters.Port)

	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	log.Infof("Got OS shutdown signal, shutting down webhook server gracefully...")
	//whsvr.Server.Shutdown(context.Background())

}

func init() {
	options.NewWhSvrParameters()

	level := log.Level(options.Parameters.Logv)
	log.SetLevel(level)
	fmt.Printf("日志级别：%s\n", log.GetLevel())
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

}
