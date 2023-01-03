/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package identity_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/hxx258456/ccgo/x509"

	"github.com/hxx258456/ccgo/sm2"
)

// NewECDSAPrivateKey generates a new private key for testing
func NewSM2PrivateKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

func publicKey(priv crypto.PrivateKey) crypto.PublicKey {
	switch k := priv.(type) {
	case *sm2.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// NewCertificate generates a new certificate from a private key for testing
func NewCertificate(privateKey crypto.PrivateKey) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: []string{"test.example.org"},
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privateKey), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	return x509.ParseCertificate(certificateBytes)
}
