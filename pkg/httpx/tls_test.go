package httpx

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/testify/v2/require"

	"github.com/spegel-org/spegel/internal/testutil"
)

func TestMutualTLSConfigs(t *testing.T) {
	t.Parallel()

	caPool, cert := testutil.NewCA(t, "spegel-peer")
	otherCAPool, otherCert := testutil.NewCA(t, "spegel-peer")

	_, _, err := MutualTLSConfigs(nil, cert, "spegel-peer")
	require.Error(t, err)
	_, _, err = MutualTLSConfigs(caPool, nil, "spegel-peer")
	require.Error(t, err)
	_, _, err = MutualTLSConfigs(caPool, cert, "")
	require.Error(t, err)

	serverCfg, clientCfg, err := MutualTLSConfigs(caPool, cert, "spegel-peer")
	require.NoError(t, err)
	require.EqualT(t, tls.RequireAndVerifyClientCert, serverCfg.ClientAuth)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	get := func(cfg *tls.Config, url string) error {
		transport := BaseTransport()
		transport.TLSClientConfig = cfg
		client := &http.Client{Transport: transport}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code %d", resp.StatusCode)
		}
		return nil
	}

	// Mutually authenticated peer.
	err = get(clientCfg, srv.URL)
	require.NoError(t, err)

	// No client certificate.
	noCertCfg := clientCfg.Clone()
	noCertCfg.Certificates = nil
	err = get(noCertCfg, srv.URL)
	require.Error(t, err)

	// Client certificate signed by another CA.
	_, otherClientCfg, err := MutualTLSConfigs(caPool, otherCert, "spegel-peer")
	require.NoError(t, err)
	err = get(otherClientCfg, srv.URL)
	require.Error(t, err)

	// Server certificate not trusted by the client.
	_, untrustingCfg, err := MutualTLSConfigs(otherCAPool, cert, "spegel-peer")
	require.NoError(t, err)
	err = get(untrustingCfg, srv.URL)
	require.Error(t, err)

	// Server certificate for another name.
	_, wrongNameCfg, err := MutualTLSConfigs(caPool, cert, "other-name")
	require.NoError(t, err)
	err = get(wrongNameCfg, srv.URL)
	require.Error(t, err)

	// Plain HTTP.
	err = get(nil, "http://"+srv.Listener.Addr().String())
	require.Error(t, err)
}
