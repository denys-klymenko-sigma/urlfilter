// Package main is responsible for the command-line interface of the urlfilter
// content filtering proxy.
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/denys-klymenko-sigma/urlfilter/proxy"
	goFlags "github.com/jessevdk/go-flags"
)

// Options -- console arguments
type Options struct {
	// LogOutput - path to the log file
	LogOutput string `short:"o" long:"output" description:"Path to the log file. If not set, it writes to stderr." default:""`

	// ListenAddr - server listen address
	ListenAddr string `short:"l" long:"listen" description:"Listen address." default:"0.0.0.0"`

	// TLSCertPath - path to the .crt with the certificate chain
	TLSCertPath string `short:"c" long:"ca-cert" description:"Path to a file with the root certificate." required:"true"`

	// TLSKeyPath - path to the file with the private key
	TLSKeyPath string `short:"k" long:"ca-key" description:"Path to a file with the CA private key." required:"true"`

	// Proxy username
	ProxyUser string `short:"u" long:"username" description:"Proxy auth username. If specified, proxy authorization is required."`

	// ProxyPassword - proxy password
	ProxyPassword string `short:"a" long:"password" description:"Proxy auth password. If specified, proxy authorization is required."`

	// HTTPSHostname - server name for the HTTPS proxy.
	HTTPSHostname string `short:"n" long:"https-name" description:"Server name or IP address of the HTTPS proxy."`

	// FilterLists - paths to the filter lists
	FilterLists []string `short:"f" long:"filter" description:"Path to the filter list. Can be specified multiple times."`

	// ListenPort - server listen port
	ListenPort int `short:"p" long:"port" description:"Listen port. Zero value disables TCP and UDP listeners." default:"8080"`

	// HTTPSProxy - if specified, start a HTTPS proxy. Otherwise, it will start an HTTP proxy.
	HTTPSProxy bool `short:"t" long:"https" description:"Run an HTTPS proxy (otherwise, it runs plain HTTP proxy)." optional:"yes" optional-value:"true"`

	// Verbose - should we write debug-level log
	Verbose bool `short:"v" long:"verbose" description:"Verbose output (optional)." optional:"yes" optional-value:"true"`
}

func main() {
	var options Options
	parser := goFlags.NewParser(&options, goFlags.Default)

	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*goFlags.Error); ok && flagsErr.Type == goFlags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	run(options)
}

func run(options Options) {
	if options.Verbose {
		log.SetLevel(log.DEBUG)
	}
	if options.LogOutput != "" {
		// nolint: gosec
		file, err := os.OpenFile(options.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatalf("cannot create a log file: %s", err)
		}
		defer log.OnCloserError(file, log.ERROR)
		log.SetOutput(file)
	}

	log.Printf("starting proxy")

	config := createServerConfig(options)
	server, err := proxy.NewServer(config)
	if err != nil {
		log.Fatalf("failed to create new proxy server: %v", err)
	}

	err = server.Start()
	if err != nil {
		log.Fatalf("failed to start the proxy server: %v", err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// CLOSE THE PROXY
	server.Close()
}

func createServerConfig(options Options) proxy.Config {
	listenIP, err := netip.ParseAddr(options.ListenAddr)
	if err != nil {
		log.Fatalf("parsing listen addr: %s", err)
	}

	mitmConfig := createMITMConfig(options)

	var tlsConfig *tls.Config
	if options.HTTPSProxy {
		if options.HTTPSHostname == "" {
			log.Fatalf("HTTPS hostname must be specified")
		}

		var proxyCert *tls.Certificate
		proxyCert, err = mitmConfig.GetOrCreateCert(options.HTTPSHostname)
		if err != nil {
			log.Fatalf("failed to generate HTTPS proxy certificate for %s: %v", options.HTTPSHostname, err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*proxyCert},
			ServerName:   options.HTTPSHostname,
			// gosec is triggered when the TLS version is set to less than 1.2.
			MinVersion: tls.VersionTLS12,
		}
	}

	config := proxy.Config{
		FiltersPaths:          map[int]string{},
		CompressContentScript: true,
	}
	for i, v := range options.FilterLists {
		config.FiltersPaths[i] = v
	}

	// TODO(e.burkov):  Use netip.AddrPort when gomitmproxy will support it.
	addr := &net.TCPAddr{IP: listenIP.AsSlice(), Port: options.ListenPort}
	config.ProxyConfig = gomitmproxy.Config{
		ListenAddr: addr,
		TLSConfig:  tlsConfig,

		Username: options.ProxyUser,
		Password: options.ProxyPassword,
		APIHost:  "adguard",

		MITMConfig:     mitmConfig,
		MITMExceptions: []string{"example.com"},
	}

	return config
}

func createMITMConfig(options Options) *mitm.Config {
	tlsCert, err := tls.LoadX509KeyPair(options.TLSCertPath, options.TLSKeyPath)
	if err != nil {
		log.Fatalf("failed to load root CA: %v", err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatalf("invalid certificate: %v", err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		log.Fatalf("failed to create MITM config: %v", err)
	}

	mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
	mitmConfig.SetOrganization("AdGuard")      // cert organization
	return mitmConfig
}
