package hccgn

import (
	"encoding/hex"
	"testing"
)

func TestKnownAnswerVector(t *testing.T) {
	rawHex := "484343474e573031000116ae5342937422ee10b0e9640983086ee692b6fa78482506a5a1b807ce14ee50000000000000000010000000000000001000000006553f1001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200017b80000005ee000000050007000000000000002affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	raw, err := hex.DecodeString(rawHex); if err != nil { t.Fatal(err) }
	wantNetwork, _ := hex.DecodeString("16ae5342937422ee10b0e9640983086ee692b6fa78482506a5a1b807ce14ee50")
	target := make([]byte, 32); for i := range target { target[i] = 0xff }
	digest, err := WorkDigest(raw); if err != nil { t.Fatal(err) }
	if got := hex.EncodeToString(digest); got != "c823ee2a5d77e8576b1b4213bcdcca983b31c8b1c55743059f240957d9467f71" { t.Fatalf("digest=%s", got) }
	proof := append([]byte("HCCGN-PROOF/1\x00"), HeaderSize>>8, byte(HeaderSize))
	proof = append(proof, raw...); proof = append(proof, digest...)
	if got := ProofHash(proof); got != "b48d21de1459758e3ffa8ed5a6e8a4488491787a4cd285bd93def24d3b36bb57" { t.Fatalf("proof hash=%s", got) }
	h, verified, err := VerifyProof(proof, wantNetwork, target)
	if err != nil { t.Fatal(err) }
	if h.Nonce != 42 || hex.EncodeToString(verified) != hex.EncodeToString(digest) { t.Fatal("decoded proof mismatch") }
}

func TestLowTargetKnownAnswerRejected(t *testing.T) {
	rawHex := "484343474e573031000116ae5342937422ee10b0e9640983086ee692b6fa78482506a5a1b807ce14ee50000000000000000010000000000000001000000006553f1001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200017b80000005ee000000050007000000000000002a00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	raw, err := hex.DecodeString(rawHex); if err != nil { t.Fatal(err) }
	network, _ := hex.DecodeString("16ae5342937422ee10b0e9640983086ee692b6fa78482506a5a1b807ce14ee50")
	target := append([]byte{0}, bytesRepeat(0xff, 31)...)
	digest, err := WorkDigest(raw); if err != nil { t.Fatal(err) }
	if got := hex.EncodeToString(digest); got != "0654fc8c10a9a9a5dbb4ad82c6621608f5b596fb053cc6a467a9b3a6fdb70560" { t.Fatalf("digest=%s", got) }
	proof := append([]byte("HCCGN-PROOF/1\x00"), HeaderSize>>8, byte(HeaderSize))
	proof = append(proof, raw...); proof = append(proof, digest...)
	if got := ProofHash(proof); got != "6aa84b5c7f01360a8f133d4a2144e7e333845905102eec7c0ba5ba1a62db3b2e" { t.Fatalf("proof hash=%s", got) }
	if _, _, err := VerifyProof(proof, network, target); err == nil || err.Error() != "work_target_not_met" { t.Fatalf("expected work_target_not_met, got %v", err) }
}

func bytesRepeat(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out { out[i] = value }
	return out
}
