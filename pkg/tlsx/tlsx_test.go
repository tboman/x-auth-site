package tlsx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/logx"
)

// certFixture generates a CA plus a leaf signed by it and writes all PEMs to
// dir, returning the file paths.
type certFixture struct {
	caFile, certFile, keyFile string
}

func newFixture(t *testing.T, dir, cn string) certFixture {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn + "-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	write := func(name string, blockType string, der []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	f := certFixture{
		caFile:   write(cn+"-ca.pem", "CERTIFICATE", caDER),
		certFile: write(cn+".pem", "CERTIFICATE", leafDER),
	}
	f.keyFile = write(cn+"-key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(leafKey))
	return f
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{EnvCertFile, EnvKeyFile, EnvClientCAFile, EnvCAFile} {
		t.Setenv(v, "")
	}
}

func TestUnconfiguredIsPlaintext(t *testing.T) {
	clearEnv(t)
	logger := logx.New("tlsx-test")

	sc, err := ServerConfig(logger)
	if err != nil || sc != nil {
		t.Fatalf("want nil server config, got %v / %v", sc, err)
	}
	cc, err := ClientConfig(logger)
	if err != nil || cc != nil {
		t.Fatalf("want nil client config, got %v / %v", cc, err)
	}
	rt, err := Transport(logger)
	if err != nil || rt != http.DefaultTransport {
		t.Fatalf("want default transport, got %v / %v", rt, err)
	}
}

func TestPartialConfigErrors(t *testing.T) {
	clearEnv(t)
	logger := logx.New("tlsx-test")
	t.Setenv(EnvCertFile, "cert.pem") // key missing

	if _, err := ServerConfig(logger); !errors.Is(err, ErrPartialConfig) {
		t.Fatalf("server: want ErrPartialConfig, got %v", err)
	}
	if _, err := ClientConfig(logger); !errors.Is(err, ErrPartialConfig) {
		t.Fatalf("client: want ErrPartialConfig, got %v", err)
	}
}

func TestMutualTLSEndToEnd(t *testing.T) {
	clearEnv(t)
	logger := logx.New("tlsx-test")
	dir := t.TempDir()
	server := newFixture(t, dir, "server")
	client := newFixture(t, dir, "client")

	// Server: own cert, requires client certs signed by the client CA.
	t.Setenv(EnvCertFile, server.certFile)
	t.Setenv(EnvKeyFile, server.keyFile)
	t.Setenv(EnvClientCAFile, client.caFile)
	serverConf, err := ServerConfig(logger)
	if err != nil {
		t.Fatalf("server config: %v", err)
	}
	if serverConf.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("want RequireAndVerifyClientCert, got %v", serverConf.ClientAuth)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no peer cert", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("ok " + r.TLS.PeerCertificates[0].Subject.CommonName))
	}))
	srv.TLS = serverConf
	srv.StartTLS()
	defer srv.Close()
	// httptest.StartTLS appends its own cert; restore ours as the only one so
	// the client's CA check exercises the fixture chain.
	srv.TLS.Certificates = serverConf.Certificates

	// Client: trusts the server CA, presents the client cert.
	t.Setenv(EnvCertFile, client.certFile)
	t.Setenv(EnvKeyFile, client.keyFile)
	t.Setenv(EnvCAFile, server.caFile)
	rt, err := Transport(logger)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	httpClient := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	resp, err := httpClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok client" {
		t.Fatalf("want 200 'ok client', got %d %q", resp.StatusCode, body)
	}

	// A client WITHOUT a certificate must be rejected during the handshake.
	t.Setenv(EnvCertFile, "")
	t.Setenv(EnvKeyFile, "")
	rtNoCert, err := Transport(logger)
	if err != nil {
		t.Fatalf("no-cert transport: %v", err)
	}
	noCertClient := &http.Client{Transport: rtNoCert, Timeout: 5 * time.Second}
	if _, err := noCertClient.Get(srv.URL); err == nil {
		t.Fatal("client without certificate must fail the mTLS handshake")
	}
}

func TestServerRejectsUntrustedClientCert(t *testing.T) {
	clearEnv(t)
	logger := logx.New("tlsx-test")
	dir := t.TempDir()
	server := newFixture(t, dir, "server")
	trusted := newFixture(t, dir, "client")
	rogue := newFixture(t, dir, "rogue") // different CA entirely

	t.Setenv(EnvCertFile, server.certFile)
	t.Setenv(EnvKeyFile, server.keyFile)
	t.Setenv(EnvClientCAFile, trusted.caFile)
	serverConf, err := ServerConfig(logger)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = serverConf
	srv.StartTLS()
	defer srv.Close()
	srv.TLS.Certificates = serverConf.Certificates

	t.Setenv(EnvCertFile, rogue.certFile)
	t.Setenv(EnvKeyFile, rogue.keyFile)
	t.Setenv(EnvCAFile, server.caFile)
	rt, err := Transport(logger)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: rt, Timeout: 5 * time.Second}
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("certificate from an untrusted CA must fail the handshake")
	}
}
