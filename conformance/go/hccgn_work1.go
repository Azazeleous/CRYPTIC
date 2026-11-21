// Package hccgn implements an independent standard-library HCCGN-WORK/1 verifier.
package hccgn

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
)

const HeaderSize = 184
var workDomain = []byte("HCCGN-WORK/1\x00")
var proofDomain = []byte("HCCGN-PROOF/1\x00")

type Header struct {
	Raw []byte
	NetworkIDHash []byte
	Height, Sequence, Timestamp uint64
	ParentHash, PayloadHash []byte
	PrimaryStride uint32
	CompactStride uint16
	Nonce uint64
	Target []byte
}

func gcd(a, b uint64) uint64 { for b != 0 { a, b = b, a%b }; return a }

func DecodeHeader(raw []byte) (*Header, error) {
	if len(raw) != HeaderSize { return nil, errors.New("header_length_invalid") }
	if string(raw[0:8]) != "HCCGNW01" { return nil, errors.New("header_magic_invalid") }
	if binary.BigEndian.Uint16(raw[8:10]) != 1 { return nil, errors.New("work_version_unsupported") }
	if binary.BigEndian.Uint32(raw[130:134]) != 97152 || binary.BigEndian.Uint32(raw[134:138]) != 1518 {
		return nil, errors.New("residue_modulus_mismatch")
	}
	ps := binary.BigEndian.Uint32(raw[138:142])
	cs := binary.BigEndian.Uint16(raw[142:144])
	if ps == 0 || ps >= 97152 || gcd(uint64(ps), 97152) != 1 { return nil, errors.New("primary_stride_not_coprime") }
	if cs == 0 || cs >= 1518 || gcd(uint64(cs), 1518) != 1 { return nil, errors.New("compact_stride_not_coprime") }
	h := &Header{
		Raw: append([]byte(nil), raw...), NetworkIDHash: append([]byte(nil), raw[10:42]...),
		Height: binary.BigEndian.Uint64(raw[42:50]), Sequence: binary.BigEndian.Uint64(raw[50:58]),
		Timestamp: binary.BigEndian.Uint64(raw[58:66]), ParentHash: append([]byte(nil), raw[66:98]...),
		PayloadHash: append([]byte(nil), raw[98:130]...), PrimaryStride: ps, CompactStride: cs,
		Nonce: binary.BigEndian.Uint64(raw[144:152]), Target: append([]byte(nil), raw[152:184]...),
	}
	if h.Height == 0 || h.Sequence == 0 { return nil, errors.New("header_position_invalid") }
	return h, nil
}

func WorkDigest(raw []byte) ([]byte, error) {
	if len(raw) != HeaderSize { return nil, errors.New("header_length_invalid") }
	input := make([]byte, 0, len(workDomain)+len(raw))
	input = append(input, workDomain...)
	input = append(input, raw...)
	d := sha256.Sum256(input)
	return d[:], nil
}

func ProofHash(proof []byte) string { d := sha256.Sum256(proof); return hex.EncodeToString(d[:]) }

func VerifyProof(proof, expectedNetworkHash, expectedTarget []byte) (*Header, []byte, error) {
	minimum := len(proofDomain)+2+HeaderSize+32
	if len(proof) != minimum { return nil, nil, errors.New("proof_envelope_length_invalid") }
	if string(proof[:len(proofDomain)]) != string(proofDomain) { return nil, nil, errors.New("proof_envelope_magic_invalid") }
	offset := len(proofDomain)
	if binary.BigEndian.Uint16(proof[offset:offset+2]) != HeaderSize { return nil, nil, errors.New("proof_header_length_invalid") }
	raw := proof[offset+2:offset+2+HeaderSize]
	h, err := DecodeHeader(raw); if err != nil { return nil, nil, err }
	digest, err := WorkDigest(raw); if err != nil { return nil, nil, err }
	claimed := proof[offset+2+HeaderSize:]
	if string(claimed) != string(digest) { return nil, nil, errors.New("work_digest_mismatch") }
	if len(expectedNetworkHash) != 32 || string(h.NetworkIDHash) != string(expectedNetworkHash) { return nil, nil, errors.New("network_id_mismatch") }
	if len(expectedTarget) != 32 || string(h.Target) != string(expectedTarget) { return nil, nil, errors.New("active_target_mismatch") }
	if new(big.Int).SetBytes(digest).Cmp(new(big.Int).SetBytes(expectedTarget)) > 0 { return nil, nil, errors.New("work_target_not_met") }
	return h, digest, nil
}
