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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
)

// Security constants
const TimestampToleranceMs = 30000 // ±30 seconds for timestamp validation

type IdentityPayload struct {
	SessionID      string                 `json:"session_id"`
	Timestamp      int64                  `json:"timestamp"`
	Nonce          string                 `json:"nonce"`
	AccessToken    string                 `json:"access_token,omitempty"`    // Optional OpenID token for enhanced verification
	DeviceID       string                 `json:"device_id,omitempty"`       // Device ID in request
	UserInfo       map[string]interface{} `json:"user_info,omitempty"`       // Optional user info in response
	DeviceValidity string                 `json:"device_validity,omitempty"` // Device validation result in response
}

type IdentityRequest struct {
	Payload   IdentityPayload `json:"payload"`
	Signature string          `json:"signature"`
}

type IdentityResponse struct {
	Payload   IdentityPayload `json:"payload"`
	Signature string          `json:"signature"`
}

func generateNonce() (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonce), nil
}

func canonicalJSON(v interface{}) ([]byte, error) {
	// Matrix canonical JSON requires keys to be sorted alphabetically
	// Convert to map first to ensure key ordering
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	// Marshal again with sorted keys (Go's json package sorts keys by default)
	result, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	debugLog("Canonical JSON: %s", string(result))
	return result, nil
}

func signPayload(payload IdentityPayload, privateKey ed25519.PrivateKey) (string, error) {
	payloadBytes, err := canonicalJSON(payload)
	if err != nil {
		debugLog("Failed to marshal payload: %v", err)
		return "", err
	}

	debugLog("Signing payload: %s", string(payloadBytes))

	signature := ed25519.Sign(privateKey, payloadBytes)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	debugLog("Generated signature: %s", signatureB64)
	return signatureB64, nil
}

func verifySignature(payload IdentityPayload, signature string, publicKey ed25519.PublicKey) error {
	payloadBytes, err := canonicalJSON(payload)
	if err != nil {
		return err
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// Test mode: simulate tampered signature
	if os.Getenv("LIVEKIT_TEST_FAKE_V2_SIGNATURE") == "true" {
		debugLog("TEST MODE: Simulating tampered signature (LIVEKIT_TEST_FAKE_V2_SIGNATURE=true)")
		// Corrupt the signature bytes to simulate tampering
		if len(sigBytes) > 0 {
			sigBytes[0] ^= 0xFF // Flip all bits in first byte
		}
	}

	if !ed25519.Verify(publicKey, payloadBytes, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func verifyIdentity(serverName string, privateKey ed25519.PrivateKey, synapsePublicKey ed25519.PublicKey) error {
	return verifyIdentityWithToken(serverName, "", privateKey, synapsePublicKey)
}

func verifyIdentityWithToken(serverName, accessToken string, privateKey ed25519.PrivateKey, synapsePublicKey ed25519.PublicKey) error {
	// SECURITY FIX: Validate server name to prevent SSRF attacks
	isPublicFacing := os.Getenv("LIVEKIT_IS_PUBLIC_FACING") == "true"
	if err := validateMatrixServerName(serverName, isPublicFacing); err != nil {
		return fmt.Errorf("invalid server name: %v", err)
	}

	// Generate nonce first to handle errors properly
	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("nonce generation failed: %v", err)
	}

	// Generate request payload
	payload := IdentityPayload{
		SessionID:   uuid.New().String(),
		Timestamp:   time.Now().UnixMilli(),
		Nonce:       nonce,
		AccessToken: accessToken, // Include access token if provided
	}

	// Sign payload
	signature, err := signPayload(payload, privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign payload: %v", err)
	}

	// Create request
	request := IdentityRequest{
		Payload:   payload,
		Signature: signature,
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	// Send request to Synapse
	u := &url.URL{
		Scheme: "https",
		Host:   serverName,
		Path:   "/_matrix/client/r0/identity/verify",
	}
	debugLog("Sending identity verification request to: %s", u.String())
	debugLog("Request payload: %s", string(reqBody))

	// Create context with deadline aligned to server write timeout (3s)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		debugLog("HTTP request failed: %v", err)
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Limit response headers to 100 (5x observed ~20 headers)
	if len(resp.Header) > 100 {
		return fmt.Errorf("too many response headers: %d", len(resp.Header))
	}

	debugLog("Response status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		// Read response body for error details (limit to 10KB)
		var responseBody []byte
		if responseBody, err = io.ReadAll(io.LimitReader(resp.Body, 10240)); err == nil {
			debugLog("Error response body: %s", string(responseBody))
		}
		return fmt.Errorf("verification failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	// Parse response (limit to 10KB)
	dec := json.NewDecoder(io.LimitReader(resp.Body, 10240))
	var response IdentityResponse
	if err := dec.Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	// Verify response
	debugLog("Verifying response - SessionID: %s vs %s, Nonce: %s vs %s", response.Payload.SessionID, payload.SessionID, response.Payload.Nonce, payload.Nonce)
	if response.Payload.SessionID != payload.SessionID {
		return fmt.Errorf("session ID mismatch: got %s, expected %s", response.Payload.SessionID, payload.SessionID)
	}
	if response.Payload.Nonce != payload.Nonce {
		return fmt.Errorf("nonce mismatch: got %s, expected %s", response.Payload.Nonce, payload.Nonce)
	}
	debugLog("Session ID and nonce validation passed")

	// Check timestamp within tolerance
	currentTime := time.Now().UnixMilli()
	timeDiff := currentTime - response.Payload.Timestamp
	debugLog("Timestamp validation - Current: %d, Response: %d, Diff: %d ms", currentTime, response.Payload.Timestamp, timeDiff)
	if timeDiff < -TimestampToleranceMs || timeDiff > TimestampToleranceMs {
		debugLog("Timestamp out of range: %d ms (allowed: ±%d ms)", timeDiff, TimestampToleranceMs)
		return fmt.Errorf("timestamp out of range: %d ms", timeDiff)
	}
	debugLog("Timestamp validation passed")

	// Verify Synapse signature
	if err := verifySignature(response.Payload, response.Signature, synapsePublicKey); err != nil {
		return fmt.Errorf("synapse signature verification failed: %v", err)
	}

	return nil
}
