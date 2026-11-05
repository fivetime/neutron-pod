package l7

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/keymanager/v1/secrets"
	corev1 "k8s.io/api/core/v1"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// EnsureBarbicanSecret mirrors a K8s TLS Secret into Barbican as a PKCS12
// bundle and returns its reference (the value TERMINATED_HTTPS listeners take
// as default_tls_container_ref). Idempotent AND rotation-aware: the Barbican
// secret name embeds a content hash, so
//   - unchanged cert  -> the existing secret is found by exact name and reused;
//   - rotated cert    -> a NEW name is created, the caller re-points the
//     listener, and every stale same-prefix secret is deleted afterwards
//     (CleanupBarbicanSecrets). Renaming-on-rotate is what makes "update"
//     atomic — Barbican secrets are immutable, an in-place update is not a
//     thing (same scheme as the upstream controller's name-per-content).
//
// PKCS12 encoding matches the upstream octavia-ingress-controller
// (LegacyRC2 + empty password) — the exact shape Octavia's cert_parser
// expects from a Barbican secret payload.
func EnsureBarbicanSecret(ctx context.Context, km *gophercloud.ServiceClient, name string, tlsSecret *corev1.Secret) (string, error) {
	if km == nil {
		return "", fmt.Errorf("this deployment has no key-manager (Barbican) endpoint; TERMINATED_HTTPS Ingress needs one")
	}
	crt, key := tlsSecret.Data[corev1.TLSCertKey], tlsSecret.Data[corev1.TLSPrivateKeyKey]
	if len(crt) == 0 || len(key) == 0 {
		return "", fmt.Errorf("TLS Secret %s/%s misses %s or %s", tlsSecret.Namespace, tlsSecret.Name, corev1.TLSCertKey, corev1.TLSPrivateKeyKey)
	}

	sum := sha256.Sum256(append(append([]byte{}, crt...), key...))
	full := fmt.Sprintf("%s_%s", name, hex.EncodeToString(sum[:])[:10])

	// Reuse by exact name (content unchanged).
	pages, err := secrets.List(km, secrets.ListOpts{Name: full}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("listing Barbican secrets %q: %w", full, err)
	}
	existing, err := secrets.ExtractSecrets(pages)
	if err != nil {
		return "", err
	}
	if len(existing) > 0 {
		return existing[0].SecretRef, nil
	}

	pfx, err := toPKCS12(crt, key)
	if err != nil {
		return "", fmt.Errorf("encoding TLS Secret %s/%s as PKCS12: %w", tlsSecret.Namespace, tlsSecret.Name, err)
	}
	created, err := secrets.Create(ctx, km, secrets.CreateOpts{
		Name:                   full,
		Payload:                base64.StdEncoding.EncodeToString(pfx),
		PayloadContentType:     "application/octet-stream",
		PayloadContentEncoding: "base64",
		SecretType:             secrets.OpaqueSecret,
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("storing Barbican secret %q: %w", full, err)
	}
	return created.SecretRef, nil
}

// CleanupBarbicanSecrets deletes every Barbican secret the caller owns whose
// name starts with prefix, except the ones whose ref is in keep. Serves both
// rotation (keep = the refs the listener now uses) and Ingress deletion
// (keep = nil).
func CleanupBarbicanSecrets(ctx context.Context, km *gophercloud.ServiceClient, prefix string, keep map[string]bool) error {
	if km == nil {
		return nil
	}
	// Barbican's name filter is exact-match, so list the project's secrets and
	// filter by prefix here. Tenant-scoped credential -> tenant-sized list.
	pages, err := secrets.List(km, secrets.ListOpts{}).AllPages(ctx)
	if err != nil {
		return fmt.Errorf("listing Barbican secrets for cleanup: %w", err)
	}
	all, err := secrets.ExtractSecrets(pages)
	if err != nil {
		return err
	}
	for i := range all {
		s := &all[i]
		if !strings.HasPrefix(s.Name, prefix) || keep[s.SecretRef] {
			continue
		}
		id := s.SecretRef[strings.LastIndex(s.SecretRef, "/")+1:]
		if err := secrets.Delete(ctx, km, id).ExtractErr(); err != nil && !gophercloud.ResponseCodeIs(err, 404) {
			return fmt.Errorf("deleting Barbican secret %s: %w", s.Name, err)
		}
	}
	return nil
}

// toPKCS12 converts a PEM certificate chain + PEM private key into the PKCS12
// bundle Octavia expects (leaf + key + intermediates as CA entries).
func toPKCS12(crtPEM, keyPEM []byte) ([]byte, error) {
	var chain []*x509.Certificate
	for rest := crtPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block in tls.crt")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in tls.key")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return pkcs12.LegacyRC2.WithRand(rand.Reader).Encode(key, chain[0], chain[1:], "")
}

// parsePrivateKey tries the three PEM private-key encodings cert-manager and
// openssl produce (PKCS8, PKCS1/RSA, SEC1/EC).
func parsePrivateKey(der []byte) (any, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("tls.key is not PKCS8/PKCS1/EC")
}
