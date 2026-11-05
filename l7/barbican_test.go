package l7

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func selfSigned(t *testing.T, cn string, key any, pub any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// cert-manager and openssl produce all three private key encodings.
func TestToPKCS12ReadsEveryKeyEncoding(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		crt  []byte
		key  []byte
	}{
		{"PKCS1", selfSigned(t, "a", rsaKey, &rsaKey.PublicKey), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})},
		{"PKCS8", selfSigned(t, "b", ecKey, &ecKey.PublicKey), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})},
		{"SEC1", selfSigned(t, "c", ecKey, &ecKey.PublicKey), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})},
	} {
		pfx, err := toPKCS12(tc.crt, tc.key)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		// Octavia's cert_parser reads the bundle with an empty password.
		if _, _, _, err := pkcs12.DecodeChain(pfx, ""); err != nil {
			t.Fatalf("%s: bundle does not decode: %v", tc.name, err)
		}
	}
}

func TestToPKCS12RefusesGarbage(t *testing.T) {
	if _, err := toPKCS12([]byte("nope"), []byte("nope")); err == nil {
		t.Fatal("no CERTIFICATE block must be an error")
	}
}

// No key-manager endpoint is a clear refusal for a TLS Ingress, and nothing to clean
// for the rest.
func TestNoKeyManager(t *testing.T) {
	ctx := context.Background()
	if _, err := EnsureBarbicanSecret(ctx, nil, "n", &corev1.Secret{}); err == nil {
		t.Fatal("TLS without Barbican must be refused")
	}
	if err := CleanupBarbicanSecrets(ctx, nil, "p", nil); err != nil {
		t.Fatalf("cleanup without Barbican = %v", err)
	}
}
