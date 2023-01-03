/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package identity

import (
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/ccgo/sm3"
)

func sm2PrivateKeySign(privateKey *sm2.PrivateKey) signFn {
	n := privateKey.Params().Params().N

	return func(message []byte) ([]byte, error) {
		digest := sm3.Sm3Sum(message)
		r, s, err := sm2.Sign(rand.Reader, privateKey, digest[:])
		if err != nil {
			return nil, err
		}

		s = canonicalSM2SignatureSValue(s, n)

		return asn1SM2Signature(r, s)
	}
}

func canonicalSM2SignatureSValue(s *big.Int, curveN *big.Int) *big.Int {
	halfOrder := new(big.Int).Rsh(curveN, 1)
	if s.Cmp(halfOrder) <= 0 {
		return s
	}

	// Set s to N - s so it is in the lower part of signature space, less or equal to half order
	return new(big.Int).Sub(curveN, s)
}

type sm2Signature struct {
	R, S *big.Int
}

func asn1SM2Signature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(sm2Signature{
		R: r,
		S: s,
	})
}
