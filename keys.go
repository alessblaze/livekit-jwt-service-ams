/*
LIVEKIT-JWT-SERVICE-AMS High Performance Security Enhanched Livekit JWT Service
Copyright (c) 2025 Albert Blasczykowski (Aless Microsystems)

This program is licensed under the Aless Microsystems Source-Available License (Non-Commercial, No Military) v1.0 Available in the Root
Directory of the project as LICENSE in Text Format.
You may use, copy, modify, and distribute this program for Non-Commercial purposes only, subject to the terms of that license.
Use by or for military, intelligence, or defense entities or purposes is strictly prohibited.

If you distribute this program in object form or make it available to others over a network, you must provide the complete
corresponding source code for the provided functionality under this same license.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the License for details.

You should have received a copy of the License along with this program; if not, see the LICENSE file included with this source.
*/

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

func loadEd25519Keys() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	// Helper: decode standard base64 (padded), falling back to unpadded.
	tryStd := func(s string) ([]byte, error) {
		s = strings.TrimSpace(s)
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		return base64.RawStdEncoding.DecodeString(s)
	}
	// Helper: best-effort zeroing for sensitive buffers.
	zero := func(b []byte) {
		for i := range b {
			b[i] = 0
		}
	}

	// Private key: 32-byte seed or 64-byte expanded private key.
	privB64 := getEnv("MATRIX_PRIVATE_KEY")
	if privB64 == "" {
		return nil, nil, fmt.Errorf("MATRIX_PRIVATE_KEY not set")
	}
	privBytes, err := tryStd(privB64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid private key: %w", err)
	}
	defer zero(privBytes)

	var priv ed25519.PrivateKey
	switch len(privBytes) {
	case ed25519.SeedSize: // 32
		priv = ed25519.NewKeyFromSeed(privBytes)
	case ed25519.PrivateKeySize: // 64
		// Copy to detach from the env buffer
		priv = ed25519.PrivateKey(append([]byte(nil), privBytes...))
	default:
		return nil, nil, fmt.Errorf("invalid private key length: got %d, want 32(seed) or 64", len(privBytes))
	}

	// Public key: exactly 32 bytes.
	pubB64 := getEnv("SYNAPSE_PUBLIC_KEY")
	if pubB64 == "" {
		return nil, nil, fmt.Errorf("SYNAPSE_PUBLIC_KEY not set")
	}
	pubBytes, err := tryStd(pubB64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize { // 32
		return nil, nil, fmt.Errorf("invalid public key length: got %d, want 32", len(pubBytes))
	}
	pub := ed25519.PublicKey(append([]byte(nil), pubBytes...))

	return priv, pub, nil
}

func generateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}
