package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func appTLSHost(appID string) string { return "app-" + hashBytes([]byte(appID))[:24] + ".internal" }

const applicationTLSRenewalWindow = 30 * 24 * time.Hour

type appCertificatePair struct {
	Certificate []byte    `json:"certificate,omitempty"`
	PrivateKey  []byte    `json:"privateKey,omitempty"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Fingerprint string    `json:"fingerprint"`
}

func parseAppCertificatePair(certificate, key []byte, appID string) (appCertificatePair, error) {
	result := appCertificatePair{}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil || len(pair.Certificate) < 2 {
		return result, errors.New("A matching application certificate and private key are required")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(appTLSHost(appID)) != nil {
		return result, errors.New("Application certificate identity does not match its resource")
	}
	issuerBytes, err := os.ReadFile(os.Getenv("APP_TLS_CA_CERT_FILE"))
	if err != nil {
		return result, err
	}
	issuerBlock, _ := pem.Decode(issuerBytes)
	if issuerBlock == nil {
		return result, errors.New("Application issuer certificate is invalid")
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil || leaf.CheckSignatureFrom(issuer) != nil {
		return result, errors.New("Application certificate was not signed by the configured issuer")
	}
	return appCertificatePair{certificate, key, leaf.NotAfter, hashBytes(leaf.Raw)}, nil
}

func readAppCertificatePair(directory, appID string) (appCertificatePair, error) {
	certificate, err := os.ReadFile(filepath.Join(directory, "app.crt"))
	if err != nil {
		return appCertificatePair{}, err
	}
	key, err := os.ReadFile(filepath.Join(directory, "app.key"))
	if err != nil {
		return appCertificatePair{}, err
	}
	return parseAppCertificatePair(certificate, key, appID)
}

// Only the trusted broker receives this intermediate key. Apps receive separate leaf keys.
func issueAppTLS(directory, appID string) error {
	return issueAppTLSBefore(directory, appID, time.Now().Add(applicationTLSRenewalWindow))
}

func issueAppTLSBefore(directory, appID string, validUntil time.Time) error {
	// A durable candidate repairs a power loss between the two atomic file renames.
	if err := recoverAppTLSInstall(directory, appID); err != nil {
		return err
	}
	existing, err := readAppCertificatePair(directory, appID)
	if err == nil && existing.ExpiresAt.After(validUntil) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	pair, err := generateAppTLS(appID, time.Now())
	if err != nil {
		return err
	}
	if !pair.ExpiresAt.After(validUntil) {
		return errors.New("Application issuer must be renewed before issuing a sufficiently long-lived leaf")
	}
	if len(existing.PrivateKey) > 0 {
		// Preserve the previous pair when an existing process has not reloaded it yet.
		if err = atomicTLSFile(filepath.Join(directory, "app.previous.key"), existing.PrivateKey); err != nil {
			return err
		}
		if err = atomicTLSFile(filepath.Join(directory, "app.previous.crt"), existing.Certificate); err != nil {
			return err
		}
	}
	if err = atomicJSON(filepath.Join(directory, ".app-tls-install.json"), pair); err != nil {
		return err
	}
	return recoverAppTLSInstall(directory, appID)
}

func generateAppTLS(appID string, now time.Time) (appCertificatePair, error) {
	empty := appCertificatePair{}
	caBytes, err := os.ReadFile(os.Getenv("APP_TLS_CA_CERT_FILE"))
	if err != nil {
		return empty, err
	}
	caBlock, _ := pem.Decode(caBytes)
	if caBlock == nil {
		return empty, errors.New("App issuer certificate is invalid")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA || !ca.NotAfter.After(now.Add(applicationTLSRenewalWindow+time.Hour)) || ca.NotBefore.After(now) {
		return empty, errors.New("Application intermediate CA must remain valid beyond the 30-day renewal window")
	}
	keyBytes, err := os.ReadFile(os.Getenv("APP_TLS_CA_KEY_FILE"))
	if err != nil {
		return empty, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return empty, errors.New("App issuer key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		parsed, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	}
	if err != nil {
		return empty, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return empty, errors.New("Unsupported application issuer key")
	}
	issuerPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || string(issuerPublic) != string(ca.RawSubjectPublicKeyInfo) {
		return empty, errors.New("Application issuer certificate and key do not match")
	}
	leaf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return empty, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return empty, err
	}
	expires := now.Add(365 * 24 * time.Hour)
	if expires.After(ca.NotAfter.Add(-time.Hour)) {
		expires = ca.NotAfter.Add(-time.Hour)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: appTLSHost(appID)}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, DNSNames: []string{appTLSHost(appID)}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &leaf.PublicKey, signer)
	if err != nil {
		return empty, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leaf)
	if err != nil {
		return empty, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caBytes...)
	return parseAppCertificatePair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), appID)
}
