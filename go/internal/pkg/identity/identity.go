/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package identity provides a set of interfaces for identity-related operations.

package identity

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/ccgo/x509"
	"github.com/hxx258456/fabric-gm/bccsp"
)

type SM2Signature struct {
	R, S *big.Int
}

// Signer is an interface which wraps the Sign method.
//
// Sign signs message bytes and returns the signature or an error on failure.
type Signer interface {
	Sign(message []byte) ([]byte, error)
}

// Serializer is an interface which wraps the Serialize function.
//
// Serialize converts an identity to bytes.  It returns an error on failure.
type Serializer interface {
	Serialize() ([]byte, error)
}

//go:generate counterfeiter -o mocks/signer_serializer.go --fake-name SignerSerializer . SignerSerializer

// SignerSerializer groups the Sign and Serialize methods.
type SignerSerializer interface {
	Signer
	Serializer
}

type CryptoImpl struct {
	Creator  []byte
	PrivKey  *sm2.PrivateKey
	SignCert *x509.Certificate
}

func (s CryptoImpl) Serialize() ([]byte, error) {
	return s.Creator, nil
}

// 对签名(r,s)做asn1编码
func MarshalSM2Signature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(SM2Signature{r, s})
}

// 对asn1编码的签名做解码
func UnmarshalSM2Signature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(SM2Signature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("invalid signature. R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("invalid signature. S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature. R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature. S must be larger than zero")
	}

	return sig.R, sig.S, nil
}

// 国密sm2签名，digest是内容摘要，opts实际没有使用
func signSM2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	signature, err = k.Sign(rand.Reader, digest, opts)
	return
}

// 国密sm2验签，digest是内容摘要，signature是被验签的签名，opts实际没有使用
func verifySM2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	valid = k.Verify(digest, signature)
	/*fmt.Printf("valid+++,%v", valid)*/
	return
}

type sm2Signer struct{}

// 在sm2Signer上绑定Sign签名方法
func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	return signSM2(k.(*SM2PrivateKey).privKey, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

// 在sm2PrivateKeyVerifier上绑定验签方法
func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(&(k.(*SM2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type sm2PublicKeyKeyVerifier struct{}

// 在sm2PublicKeyKeyVerifier上绑定验签方法
func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(k.(*SM2PublicKey).pubKey, signature, digest, opts)
}
