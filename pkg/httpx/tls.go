package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// MutualTLSConfigs returns the server and client TLS configurations for peers that
// authenticate each other with certificates signed by the given CA. Peers are dialed by
// IP, so the client verifies the server certificate against a fixed server name instead
// of the address, which allows a single certificate to be shared by all peers.
func MutualTLSConfigs(caPool *x509.CertPool, cert *tls.Certificate, serverName string) (*tls.Config, *tls.Config, error) {
	if caPool == nil {
		return nil, nil, errors.New("CA certificate is required for mutual TLS")
	}
	if cert == nil {
		return nil, nil, errors.New("TLS certificate and key are required for mutual TLS")
	}
	if serverName == "" {
		return nil, nil, errors.New("server name is required for mutual TLS")
	}
	serverCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	clientCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
		RootCAs:      caPool,
		ServerName:   serverName,
	}
	return serverCfg, clientCfg, nil
}
