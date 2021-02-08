// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"crypto/x509"
	"errors"
	"github.com/google/gopacket"
	"strconv"
)

type TLSHandshakeRecordType uint32

type TLSHandshakeRecordContent struct {
}

const (
	TLSHandshakeRecordTypeHelloRequest       TLSHandshakeRecordType = 0
	TLSHandshakeRecordTypeClientHello        TLSHandshakeRecordType = 1
	TLSHandshakeRecordTypeServerHello        TLSHandshakeRecordType = 2
	TLSHandshakeRecordTypeCertificate        TLSHandshakeRecordType = 11
	TLSHandshakeRecordTypeServerKeyExchange  TLSHandshakeRecordType = 12
	TLSHandshakeRecordTypeCertificateRequest TLSHandshakeRecordType = 13
	TLSHandshakeRecordTypeServerHelloDone    TLSHandshakeRecordType = 14
	TLSHandshakeRecordTypeCertificateVerify  TLSHandshakeRecordType = 15
	TLSHandshakeRecordTypeClientKeyExchange  TLSHandshakeRecordType = 16
	TLSHandshakeRecordTypeFinished           TLSHandshakeRecordType = 20
	TLSHandshakeRecordTypeUnknown            TLSHandshakeRecordType = 255
)

func (ht TLSHandshakeRecordType) String() string {
	switch ht {
	case TLSHandshakeRecordTypeHelloRequest:
		return "Hello Request"
	case TLSHandshakeRecordTypeClientHello:
		return "Client Hello"
	case TLSHandshakeRecordTypeServerHello:
		return "Server Hello"
	case TLSHandshakeRecordTypeCertificate:
		return "Certificate"
	case TLSHandshakeRecordTypeServerKeyExchange:
		return "Server Key Exchange"
	case TLSHandshakeRecordTypeCertificateRequest:
		return "Certificate Request"
	case TLSHandshakeRecordTypeServerHelloDone:
		return "Server Hello Done"
	case TLSHandshakeRecordTypeCertificateVerify:
		return "CertificateVerify"
	case TLSHandshakeRecordTypeClientKeyExchange:
		return "Client Key Exchange"
	case TLSHandshakeRecordTypeFinished:
		return "Handshake Finished"
	default:
		return strconv.Itoa(int(ht))
	}
}

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	HandshakeType TLSHandshakeRecordType
	Certificates  []*x509.Certificate
	Data          []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length
	t.HandshakeType = TLSHandshakeRecordType(data[0])
	if len(data) <= 3 {
		df.SetTruncated()
		return errors.New("TLS packet handshake record length mismatch")
	}
	t.Data = data[4:]
	switch t.HandshakeType {
	case TLSHandshakeRecordTypeCertificate:
		if e := t.decodeCertificate(t.Data, df); e != nil {
			return e
		}
	}
	return nil
}

func (t *TLSHandshakeRecord) decodeCertificate(data []byte, df gopacket.DecodeFeedback) error {
	var hl uint32 = 0
	if len(data) < 3 {
		df.SetTruncated()
		return errors.New("TLS packet handshake record length mismatch")
	}
	// length of all certificates = 3 bytes
	totalLength := uint32(data[hl+2]) | uint32(data[hl+1])<<8 | uint32(data[hl+0])<<16
	hl = 3
	// for each certificate
	for hl+3 < totalLength {
		// length of next certificate = 3 bytes
		certLen := uint32(data[hl+2]) | uint32(data[hl+1])<<8 | uint32(data[hl+0])<<16
		certBytes := data[hl+3 : hl+3+certLen]
		if cert, err := x509.ParseCertificate(certBytes); err == nil {
			t.Certificates = append(t.Certificates, cert)
		} else {
			return errors.New("error decoding certificate")
		}
		hl += certLen + 3
	}
	return nil
}
