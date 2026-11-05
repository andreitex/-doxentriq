package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppTLSUsesSeparateKeysAndVerifiedIssuerChain(t *testing.T) {
	root := t.TempDir()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test application issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(400 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(root, "issuer.crt"), filepath.Join(root, "issuer.key")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_TLS_CA_CERT_FILE", certFile)
	t.Setenv("APP_TLS_CA_KEY_FILE", keyFile)
	pool := x509.NewCertPool()
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(ca)
	var previous []byte
	for _, id := range []string{"app-one", "app-two"} {
		directory := filepath.Join(root, id)
		if err = os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err = issueAppTLS(directory, id); err != nil {
			t.Fatal(err)
		}
		pair, err := tls.LoadX509KeyPair(filepath.Join(directory, "app.crt"), filepath.Join(directory, "app.key"))
		if err != nil {
			t.Fatal(err)
		}
		if len(pair.Certificate) != 2 {
			t.Fatal("Leaf must include intermediate certificate")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = leaf.Verify(x509.VerifyOptions{DNSName: appTLSHost(id), Roots: pool}); err != nil {
			t.Fatal(err)
		}
		if leaf.VerifyHostname(appTLSHost("different-app")) == nil {
			t.Fatal("Cross-app hostname accepted")
		}
		if previous != nil && string(previous) == string(leaf.RawSubjectPublicKeyInfo) {
			t.Fatal("Applications share a private key")
		}
		previous = leaf.RawSubjectPublicKeyInfo
	}
}
