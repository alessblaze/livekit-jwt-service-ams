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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"

	"github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/livekit"
	lksdk "github.com/livekit/server-sdk-go/v2"

	"github.com/matrix-org/gomatrix"
)

var debugEnabled bool

// HTTP client with connection pooling (enabled only for public-facing deployments)
// SECURITY FIX: Added proper TLS configuration that was previously ignored
var httpClient *http.Client

func initHTTPClient(skipVerifyTLS bool) {
	// TODO: Think if the payload does not contain any ocsp information we can query it ourselves
	requireOCSP := os.Getenv("REQUIRE_OCSP_STAPLE") == "true"

	// Always enable connection pooling for Matrix homeserver calls (V1/V2 full access)
	transport := &http.Transport{
		MaxIdleConns:          10,               // Reduced: only need connections to trusted homeservers
		MaxIdleConnsPerHost:   2,                // Reduced: typically 1-2 homeservers per deployment
		IdleConnTimeout:       30 * time.Second, // Shorter: homeserver calls are frequent
		TLSHandshakeTimeout:   5 * time.Second,  // Shorter: homeservers should respond quickly
		ResponseHeaderTimeout: 3 * time.Second,  // Prevent header read hangs
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second, // Connection timeout
		}).DialContext,
		DisableKeepAlives: false, // Keep alive for homeserver efficiency
		ForceAttemptHTTP2: true,  // Prefer HTTP/2
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12, // Enforce TLS 1.2+
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Defensive: verify version anyway
			if cs.Version < tls.VersionTLS12 {
				return fmt.Errorf("tls version too low: %x", cs.Version)
			}

			// Debug: Log OCSP response status
			if debugEnabled {
				if len(cs.OCSPResponse) == 0 {
					log.Printf("[DEBUG] No OCSP response stapled")
				} else {
					log.Printf("[DEBUG] OCSP response present (%d bytes)", len(cs.OCSPResponse))
				}
			}

			// Optionally require a stapled OCSP response
			if requireOCSP {
				if len(cs.OCSPResponse) == 0 {
					return fmt.Errorf("missing stapled OCSP response")
				}
			}
			// If stapled OCSP is present, validate it
			if len(cs.OCSPResponse) > 0 {
				if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) < 2 {
					return fmt.Errorf("no verified chain to validate OCSP")
				}
				leaf := cs.PeerCertificates[0]
				issuer := cs.VerifiedChains[0][1]
				resp, err := ocsp.ParseResponseForCert(cs.OCSPResponse, leaf, issuer)
				if err != nil {
					return fmt.Errorf("bad OCSP staple: %w", err)
				}
				// Debug: Log OCSP response details
				if debugEnabled {
					log.Printf("[DEBUG] OCSP response: Status=%v, ThisUpdate=%v, NextUpdate=%v", resp.Status, resp.ThisUpdate, resp.NextUpdate)
				}
				// Accept only Good, within validity window
				now := time.Now()
				if resp.Status != ocsp.Good {
					return fmt.Errorf("ocsp status: %v", resp.Status)
				}
				if !resp.ThisUpdate.IsZero() && now.Before(resp.ThisUpdate.Add(-2*time.Minute)) {
					return fmt.Errorf("ocsp not yet valid")
				}
				if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate.Add(2*time.Minute)) {
					return fmt.Errorf("ocsp expired")
				}
				if debugEnabled {
					log.Printf("[DEBUG] OCSP validation passed")
				}
			}
			return nil
		},
	}

	// SECURITY FIX: Apply TLS skip verification if enabled (for development/testing only)
	if skipVerifyTLS {
		tlsConf.InsecureSkipVerify = true
	}

	transport.TLSClientConfig = tlsConf

	httpClient = &http.Client{
		Timeout:   10 * time.Second, // Shorter: homeserver calls should be fast
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// SECURITY: Prevent redirect-based SSRF by validating redirect destination
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			// Re-validate redirect destination against SSRF policy
			if err := validateServerName(req.URL.Hostname()); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}

	debugLog("HTTP client configured with TLS 1.2+ and OCSP validation (requireOCSP: %t)", requireOCSP)

	// DEVELOPMENT NOTE: skipVerifyTLS should only be enabled for local testing with self-signed certificates
	if skipVerifyTLS {
		debugLog("TLS certificate verification DISABLED for all HTTP calls - DEVELOPMENT/TESTING ONLY")
	}

	// Test OCSP functionality with a known server
	if requireOCSP {
		testOCSPFunctionality()
	}
}

func testOCSPFunctionality() {
	log.Printf("Testing OCSP functionality with cloudflare.com...")
	resp, err := httpClient.Get("https://cloudflare.com")
	if err != nil {
		log.Printf("OCSP test failed: %v", err)
		log.Printf("Your homeserver may not support OCSP stapling")
		log.Printf("Consider setting REQUIRE_OCSP_STAPLE=false")
	} else {
		resp.Body.Close()
		log.Printf("OCSP test passed - OCSP stapling is working")
	}
}

func debugLog(format string, v ...interface{}) {
	if debugEnabled {
		log.Printf("[DEBUG] "+format, v...)
	}
}

type Handler struct {
	key, secret, lkUrl    string
	fullAccessHomeservers []string
	allowedHomeservers    []string
	blockedHomeservers    []string
	skipVerifyTLS         bool
	privateKey            ed25519.PrivateKey
	synapsePublicKey      ed25519.PublicKey
	roomClient            *lksdk.RoomServiceClient
}

type OpenIDTokenType struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	MatrixServerName string `json:"matrix_server_name"`
}

type SFURequest struct {
	Room        string          `json:"room"`
	OpenIDToken OpenIDTokenType `json:"openid_token"`
	DeviceID    string          `json:"device_id"`
}

type SFUResponse struct {
	URL string `json:"url"`
	JWT string `json:"jwt"`
}

func readKeySecret() (string, string) {
	// We initialize keys & secrets from environment variables
	key := os.Getenv("LIVEKIT_KEY")
	secret := os.Getenv("LIVEKIT_SECRET")
	// We initialize potential key & secret path from environment variables
	keyPath := os.Getenv("LIVEKIT_KEY_FROM_FILE")
	secretPath := os.Getenv("LIVEKIT_SECRET_FROM_FILE")
	keySecretPath := os.Getenv("LIVEKIT_KEY_FILE")

	// If keySecretPath is set we read the file and split it into two parts
	// It takes over any other initialization
	if keySecretPath != "" {
		if keySecretBytes, err := os.ReadFile(keySecretPath); err != nil {
			log.Fatal(err)
		} else {
			keySecrets := strings.Split(string(keySecretBytes), ":")
			if len(keySecrets) != 2 {
				log.Fatalf("invalid key secret file format!")
			}
			key = keySecrets[0]
			secret = keySecrets[1]
		}
	} else {
		// If keySecretPath is not set, we try to read the key and secret from files
		// If those files are not set, we return the key & secret from the environment variables
		if keyPath != "" {
			if keyBytes, err := os.ReadFile(keyPath); err != nil {
				log.Fatal(err)
			} else {
				key = string(keyBytes)
			}
		}

		if secretPath != "" {
			if secretBytes, err := os.ReadFile(secretPath); err != nil {
				log.Fatal(err)
			} else {
				secret = string(secretBytes)
			}
		}

	}

	// remove white spaces, new lines and carriage returns
	// from key and secret
	return strings.Trim(key, " \r\n"), strings.Trim(secret, " \r\n")
}

func getJoinToken(apiKey, apiSecret, room, identity string, canCreateRoom bool) (string, error) {
	debugLog("Generating JWT token for room: %s, identity: %s, canCreate: %t", room, identity, canCreateRoom)
	at := auth.NewAccessToken(apiKey, apiSecret)

	canPublish := true
	canSubscribe := true
	grant := &auth.VideoGrant{
		RoomJoin:     true,
		RoomCreate:   canCreateRoom,
		CanPublish:   &canPublish,
		CanSubscribe: &canSubscribe,
		Room:         room,
	}

	at.SetVideoGrant(grant).
		SetIdentity(identity).
		SetValidFor(time.Hour)

	token, err := at.ToJWT()
	if err != nil {
		debugLog("Failed to generate JWT token: %v", err)
		return "", err
	}
	debugLog("Successfully generated JWT token for identity: %s", identity)
	return token, nil
}

// isPrivateAddr checks if an IP address is private, loopback, or link-local
func isPrivateAddr(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	if addr.IsPrivate() { // covers RFC1918 for IPv4 and ULA for IPv6
		return true
	}
	// Additional check for IPv4 link-local (169.254.0.0/16)
	if addr.Is4() {
		linkLocal := netip.MustParsePrefix("169.254.0.0/16")
		if linkLocal.Contains(addr) {
			return true
		}
	}
	return false
}

// validateServerName performs basic SSRF validation for redirect destinations
func validateServerName(serverName string) error {
	isPublicFacing := os.Getenv("LIVEKIT_IS_PUBLIC_FACING") == "true"
	return validateMatrixServerName(serverName, isPublicFacing)
}

// SECURITY FIX: Enhanced server name validation with proper DNS resolution and IP checking
func validateMatrixServerName(serverName string, isPublicFacing bool) error {
	if !isPublicFacing {
		return nil // Skip validation for private deployments
	}

	// SECURITY FIX: Validate server name format and length to prevent injection attacks
	if len(serverName) == 0 || len(serverName) > 255 {
		return errors.New("invalid server name length")
	}

	// SECURITY FIX: Disallow IP literals for federation endpoints
	if addr, err := netip.ParseAddr(serverName); err == nil {
		return fmt.Errorf("IP literal not allowed: %s", addr.String())
	}

	// SECURITY FIX: Strict hostname character validation (ASCII LDH)
	for i, r := range serverName {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.') {
			return fmt.Errorf("invalid hostname character at position %d: %c", i, r)
		}
		if (i == 0 || i == len(serverName)-1) && r == '-' {
			return errors.New("hostname cannot start or end with hyphen")
		}
	}

	// SECURITY FIX: Resolve hostname to IP addresses and check for private/internal ranges
	addrs, err := net.LookupHost(serverName)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %v", err)
	}

	if len(addrs) == 0 {
		return errors.New("hostname resolves to no addresses")
	}

	// Check all resolved IP addresses
	for _, addrStr := range addrs {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			return fmt.Errorf("invalid IP address %s: %v", addrStr, err)
		}

		if isPrivateAddr(addr) {
			return fmt.Errorf("hostname %s resolves to private/internal address %s", serverName, addrStr)
		}
	}

	debugLog("SSRF validation passed for %s (resolves to: %v)", serverName, addrs)
	return nil
}

type UserInfo struct {
	Sub string `json:"sub"`
}

// SECURITY FIX: Replaced fclient library with direct HTTP calls for better size control
// CLEANUP: Removed unused ctx and skipVerifyTLS parameters (TLS handled globally)
func exchangeOpenIdUserInfo(
	token OpenIDTokenType, isPublicFacing bool,
) (*UserInfo, error) {
	debugLog("Exchanging OpenID token with homeserver: %s", token.MatrixServerName)

	// SECURITY FIX: Enhanced parameter validation to prevent injection attacks
	if token.AccessToken == "" || token.MatrixServerName == "" {
		return nil, errors.New("missing parameters in openid token")
	}
	if len(token.AccessToken) > 1024 || len(token.MatrixServerName) > 255 {
		return nil, errors.New("parameter length exceeds limits")
	}

	// SECURITY FIX: Validate server name if public-facing (SSRF protection)
	if err := validateMatrixServerName(token.MatrixServerName, isPublicFacing); err != nil {
		return nil, fmt.Errorf("invalid matrix server name: %v", err)
	}

	// SECURITY FIX: URL encode access token to prevent injection
	u := &url.URL{
		Scheme: "https",
		Host:   token.MatrixServerName,
		Path:   "/_matrix/federation/v1/openid/userinfo",
	}
	q := url.Values{}
	q.Set("access_token", token.AccessToken)
	u.RawQuery = q.Encode()

	debugLog("Federation endpoint: %s", u.String())
	resp, err := httpClient.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("federation request failed: %v", err)
	}
	defer resp.Body.Close()

	// SECURITY FIX: Limit response headers to prevent resource exhaustion (5x safety margin)
	if len(resp.Header) > 100 {
		return nil, fmt.Errorf("too many response headers: %d", len(resp.Header))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("federation returned status %d", resp.StatusCode)
	}

	// SECURITY FIX: True streaming size check for response body
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1024))
	var userInfo UserInfo
	if err := dec.Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// SECURITY FIX: Enhanced validation - ensure user ID format and homeserver match
	if len(userInfo.Sub) == 0 || len(userInfo.Sub) > 255 {
		return nil, fmt.Errorf("invalid user ID length: %d", len(userInfo.Sub))
	}
	userParts := strings.SplitN(userInfo.Sub, ":", 2)
	if len(userParts) != 2 || userParts[1] != token.MatrixServerName {
		return nil, fmt.Errorf("user ID doesn't match server name '%s' != '%s'", userInfo.Sub, token.MatrixServerName)
	}

	debugLog("Successfully retrieved user info: %s", userInfo.Sub)
	return &userInfo, nil
}

func (h *Handler) isFullAccessUser(matrixServerName string) bool {
	// Grant full access if wildcard '*' is present as the only entry
	if len(h.fullAccessHomeservers) == 1 && h.fullAccessHomeservers[0] == "*" {
		return true
	}

	// Check if the matrixServerName is in the list of full-access homeservers
	return slices.Contains(h.fullAccessHomeservers, matrixServerName)
}

func (h *Handler) prepareMux() *http.ServeMux {

	mux := http.NewServeMux()
	mux.HandleFunc("/sfu/get", h.handle)
	mux.HandleFunc("/healthz", h.healthcheck)
	// Add Cloudflare Tunnel compatible endpoints
	mux.HandleFunc("/livekit/jwt/sfu/get", h.handle)
	mux.HandleFunc("/livekit/healthz", h.healthcheck)

	return mux
}

func (h *Handler) writeErrorResponse(w http.ResponseWriter, statusCode int, errCode, errMsg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(gomatrix.RespError{
		ErrCode: errCode,
		Err:     errMsg,
	})
	if err != nil {
		log.Printf("failed to encode json error message! %v", err)
	}
}

func (h *Handler) healthcheck(w http.ResponseWriter, r *http.Request) {
	clientIP := getRealClientIP(r)
	log.Printf("Health check from %s - Path: %s", clientIP, r.URL.Path)

	// SECURITY FIX: Limit header count to prevent resource exhaustion attacks (5x safety margin)
	if len(r.Header) > 100 {
		h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_REQUEST", "Too many headers")
		return
	}

	if r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
		return
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func getRealClientIP(r *http.Request) string {
	// Check common reverse proxy headers in order of preference
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip // Cloudflare
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip // Nginx
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if ips := strings.Split(ip, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	return r.RemoteAddr // Fallback to direct connection
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) {
	clientIP := getRealClientIP(r)
	log.Printf("Request from %s - Path: %s - Method: %s - Origin: \"%s\"", clientIP, r.URL.Path, r.Method, r.Header.Get("Origin"))

	// SECURITY FIX: Limit header count to prevent resource exhaustion attacks (5x safety margin)
	if len(r.Header) > 100 {
		h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_REQUEST", "Too many headers")
		return
	}

	// Log all request headers for debugging
	debugLog("=== REQUEST HEADERS ===")
	for name, values := range r.Header {
		for _, value := range values {
			// SECURITY FIX: Truncate header values in logs to prevent log injection
			if len(value) > 100 {
				debugLog("Header: %s = %s... (truncated)", name, value[:100])
			} else {
				debugLog("Header: %s = %s", name, value)
			}
		}
	}
	debugLog("=== END HEADERS ===")

	// Set the CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token")

	// Handle preflight request (CORS)
	switch r.Method {
	case "OPTIONS":
		w.WriteHeader(http.StatusOK)
		return
	case "POST":
		// SECURITY FIX: True streaming size check to prevent memory exhaustion
		limitedReader := http.MaxBytesReader(w, r.Body, 3072)

		// Read with streaming size enforcement (prevents loading oversized payloads into memory)
		bodyBytes, err := io.ReadAll(limitedReader)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_REQUEST", "Request body too large or malformed")
			return
		}

		// SECURITY FIX: Validate body is not empty to prevent processing empty requests
		if len(bodyBytes) == 0 {
			log.Printf("Empty request body received")
			h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_REQUEST", "Empty request body")
			return
		}

		debugLog("=== RAW REQUEST BODY ===")
		debugLog("%s", string(bodyBytes))
		debugLog("=== END RAW BODY ===")

		// SECURITY FIX: Enhanced JSON parsing with strict validation
		var sfuAccessRequest SFURequest
		err = json.Unmarshal(bodyBytes, &sfuAccessRequest)
		if err != nil {
			log.Printf("Error decoding JSON: %v", err)
			h.writeErrorResponse(w, http.StatusBadRequest, "M_NOT_JSON", "Error decoding JSON")
			return
		}

		// Log parsed payload structure
		debugLog("=== PARSED PAYLOAD ===")
		debugLog("Room: %s", sfuAccessRequest.Room)
		debugLog("DeviceID: %s", sfuAccessRequest.DeviceID)
		debugLog("OpenIDToken.AccessToken: %s", sfuAccessRequest.OpenIDToken.AccessToken)
		debugLog("OpenIDToken.TokenType: %s", sfuAccessRequest.OpenIDToken.TokenType)
		debugLog("OpenIDToken.MatrixServerName: %s", sfuAccessRequest.OpenIDToken.MatrixServerName)
		debugLog("=== END PARSED PAYLOAD ===")

		// SECURITY FIX: Enhanced payload validation to prevent injection and malformed requests
		if sfuAccessRequest.Room == "" {
			log.Printf("Request missing room")
			h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_JSON", "Missing parameters")
			return
		}

		// SECURITY FIX: Validate room name length and format
		if len(sfuAccessRequest.Room) > 255 {
			log.Printf("Room name too long: %d characters", len(sfuAccessRequest.Room))
			h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_JSON", "Room name too long")
			return
		}

		// SECURITY FIX: Validate device ID length and format
		if len(sfuAccessRequest.DeviceID) > 255 {
			log.Printf("Device ID too long: %d characters", len(sfuAccessRequest.DeviceID))
			h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_JSON", "Device ID too long")
			return
		}
		// Validate DeviceID format if present (base64 characters allowed)
		if sfuAccessRequest.DeviceID != "" {
			for _, r := range sfuAccessRequest.DeviceID {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/') {
					log.Printf("Invalid DeviceID format: %s", sfuAccessRequest.DeviceID)
					h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_JSON", "DeviceID must contain only base64 characters")
					return
				}
			}
		}

		// SECURITY FIX: Validate OpenID token fields
		if len(sfuAccessRequest.OpenIDToken.AccessToken) > 1024 {
			log.Printf("Access token too long: %d characters", len(sfuAccessRequest.OpenIDToken.AccessToken))
			h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_JSON", "Access token too long")
			return
		}
		if len(sfuAccessRequest.OpenIDToken.MatrixServerName) > 255 {
			log.Printf("Matrix server name too long: %d characters", len(sfuAccessRequest.OpenIDToken.MatrixServerName))
			h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_JSON", "Matrix server name too long")
			return
		}

		// Validate matrix server name for public-facing deployments (false by default)
		isPublicFacing := os.Getenv("LIVEKIT_IS_PUBLIC_FACING") == "true"
		debugLog("Processing SFU request for room: %s, device: %s", sfuAccessRequest.Room, sfuAccessRequest.DeviceID)

		// Log full payload for device ID analysis
		if payloadBytes, err := json.Marshal(sfuAccessRequest); err == nil {
			debugLog("Full request payload: %s", string(payloadBytes))
		}
		debugLog("Device ID structure - Length: %d, Content: '%s'", len(sfuAccessRequest.DeviceID), sfuAccessRequest.DeviceID)

		// Debug OpenID token structure
		debugLog("OpenID Token Analysis:")
		debugLog("  AccessToken: %s", sfuAccessRequest.OpenIDToken.AccessToken)
		debugLog("  TokenType: %s", sfuAccessRequest.OpenIDToken.TokenType)
		debugLog("  MatrixServerName: %s", sfuAccessRequest.OpenIDToken.MatrixServerName)

		// Check if AccessToken looks like a JWT (has 3 parts separated by dots)
		tokenParts := strings.Split(sfuAccessRequest.OpenIDToken.AccessToken, ".")
		debugLog("  AccessToken parts count: %d", len(tokenParts))
		if len(tokenParts) == 3 {
			debugLog("  AccessToken appears to be JWT format (3 parts)")
			debugLog("  Header part length: %d", len(tokenParts[0]))
			debugLog("  Payload part length: %d", len(tokenParts[1]))
			debugLog("  Signature part length: %d", len(tokenParts[2]))
		} else {
			debugLog("  AccessToken is NOT JWT format (opaque token)")
		}
		// Determine access level first
		isFullAccessUser := h.isFullAccessUser(sfuAccessRequest.OpenIDToken.MatrixServerName)

		// Check allowed homeservers list (if set, only these are allowed)
		if len(h.allowedHomeservers) > 0 {
			if !slices.Contains(h.allowedHomeservers, sfuAccessRequest.OpenIDToken.MatrixServerName) {
				debugLog("Homeserver not in allowed list: %s", sfuAccessRequest.OpenIDToken.MatrixServerName)
				h.writeErrorResponse(w, http.StatusForbidden, "M_FORBIDDEN", "Homeserver not allowed")
				return
			}
		}

		// Check if restricted homeservers are blocked
		if !isFullAccessUser && os.Getenv("LIVEKIT_BLOCK_RESTRICTED_HOMESERVERS") == "true" {
			debugLog("Restricted homeserver blocked: %s", sfuAccessRequest.OpenIDToken.MatrixServerName)
			h.writeErrorResponse(w, http.StatusForbidden, "M_FORBIDDEN", "Restricted homeservers are not allowed")
			return
		}

		// Check blocked homeservers list (only if allowlist and block-restricted are not active)
		if len(h.allowedHomeservers) == 0 && os.Getenv("LIVEKIT_BLOCK_RESTRICTED_HOMESERVERS") != "true" {
			if len(h.blockedHomeservers) > 0 && slices.Contains(h.blockedHomeservers, sfuAccessRequest.OpenIDToken.MatrixServerName) {
				debugLog("Homeserver is blocked: %s", sfuAccessRequest.OpenIDToken.MatrixServerName)
				h.writeErrorResponse(w, http.StatusForbidden, "M_FORBIDDEN", "Homeserver is blocked")
				return
			}
		}

		// Determine verification method based on homeserver type and configuration
		verificationMethod := os.Getenv("MATRIX_VERIFICATION_METHOD")
		var userInfo *UserInfo

		if isFullAccessUser && (verificationMethod == "v1" || verificationMethod == "v2") {
			// Full access homeservers with enhanced verification
			debugLog("Full access homeserver detected - using verification method: %s", verificationMethod)

			if verificationMethod == "v2" {
				// V2: Enhanced security with homeserver + user verification
				if h.privateKey == nil || h.synapsePublicKey == nil {
					debugLog("V2 verification enabled but keys not loaded")
					h.writeErrorResponse(w, http.StatusInternalServerError, "M_UNKNOWN", "Identity verification not configured")
					return
				}
				// Step 1: Homeserver identity verification
				debugLog("V2: Performing homeserver identity verification")
				if err := verifyIdentity(sfuAccessRequest.OpenIDToken.MatrixServerName, h.privateKey, h.synapsePublicKey); err != nil {
					debugLog("V2: Homeserver identity verification failed: %v", err)
					h.writeErrorResponse(w, http.StatusUnauthorized, "M_INVALID_SIGNATURE", "Homeserver identity verification failed")
					return
				}
				debugLog("V2: Homeserver identity verified")
			}

			if verificationMethod == "v1" {
				// V1: User identity verification (same as standard federation)
				userInfo, err = exchangeOpenIdUserInfo(sfuAccessRequest.OpenIDToken, isPublicFacing)
				if err != nil {
					debugLog("V1: User identity verification failed: %v", err)
					h.writeErrorResponse(w, http.StatusUnauthorized, "M_FORBIDDEN", "Failed to validate user identity")
					return
				}
				debugLog("V1: User identity validated: %s", userInfo.Sub)
			} else if verificationMethod == "v2" {
				// V2: Enhanced user identity verification with device validation
				deviceID := sfuAccessRequest.DeviceID
				// Debug: Use fake device ID if enabled
				if os.Getenv("MATRIX_DEBUG_FAKE_DEVICE_ID") == "true" {
					deviceID = "DEBUG_FAKE_DEVICE_" + uuid.New().String()[:8]
					debugLog("🔧 DEBUG: Using fake device ID: %s (original: %s)", deviceID, sfuAccessRequest.DeviceID)
				}
				userInfo, err = h.getUserInfoViaIdentityVerify(sfuAccessRequest.OpenIDToken, deviceID, isPublicFacing)
				if err != nil {
					debugLog("V2: Enhanced user identity verification failed: %v", err)
					h.writeErrorResponse(w, http.StatusUnauthorized, "M_FORBIDDEN", "Failed to validate user identity")
					return
				}
				debugLog("V2: User identity validated via enhanced method: %s", userInfo.Sub)
			}
		} else {
			// Standard federation for restricted homeservers or when enhanced verification is disabled
			if isFullAccessUser {
				debugLog("Full access homeserver but enhanced verification disabled - using standard federation")
			} else {
				debugLog("Restricted homeserver detected - using standard federation")
			}
			userInfo, err = exchangeOpenIdUserInfo(sfuAccessRequest.OpenIDToken, isPublicFacing)
			if err != nil {
				debugLog("Federation user info lookup failed: %v", err)
				h.writeErrorResponse(w, http.StatusUnauthorized, "M_FORBIDDEN", "Failed to validate user identity")
				return
			}
			debugLog("User identity validated via federation: %s", userInfo.Sub)
		}

		// Access level already determined above

		debugLog("User access level determined: %s for server: %s",
			map[bool]string{true: "full access", false: "restricted access"}[isFullAccessUser],
			sfuAccessRequest.OpenIDToken.MatrixServerName)

		log.Printf(
			"Got Matrix user info for %s (%s)",
			userInfo.Sub,
			map[bool]string{true: "full access", false: "restricted access"}[isFullAccessUser],
		)

		// Reject if DeviceID is missing
		if sfuAccessRequest.DeviceID == "" {
			log.Printf("DeviceID is required")
			h.writeErrorResponse(w, http.StatusBadRequest, "M_BAD_JSON", "DeviceID is required")
			return
		}

		lkIdentity := userInfo.Sub + ":" + sfuAccessRequest.DeviceID
		debugLog("Creating LiveKit identity: %s", lkIdentity)

		// Check if room exists and handle duplicate sessions for existing meetings
		listCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		existingRoom, err := h.roomClient.ListRooms(listCtx, &livekit.ListRoomsRequest{
			Names: []string{sfuAccessRequest.Room},
		})
		if err != nil {
			debugLog("Failed to check room existence: %v", err)
			h.writeErrorResponse(w, http.StatusInternalServerError, "M_UNKNOWN", "Unable to verify room status")
			return
		}

		if len(existingRoom.Rooms) == 0 {
			if !isFullAccessUser {
				debugLog("Room %s does not exist - restricted user cannot create rooms", sfuAccessRequest.Room)
				h.writeErrorResponse(w, http.StatusNotFound, "M_NOT_FOUND", "Room does not exist")
				return
			}
			debugLog("Room %s does not exist - full access user will create it", sfuAccessRequest.Room)
		} else {
			// Room exists - check for duplicate sessions for all users
			debugLog("Room %s exists - checking for duplicate sessions", sfuAccessRequest.Room)
			participantsCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			participants, err := h.roomClient.ListParticipants(participantsCtx, &livekit.ListParticipantsRequest{
				Room: sfuAccessRequest.Room,
			})
			if err != nil {
				debugLog("Failed to list participants: %v", err)
				// Continue anyway - don't block on this check
			} else {
				// Debug: Print current participants
				debugLog("Current participants in room %s (%d total):", sfuAccessRequest.Room, len(participants.Participants))
				for i, participant := range participants.Participants {
					debugLog("  [%d] Identity: %s, SID: %s", i+1, participant.Identity, participant.Sid)
				}
				debugLog("Checking for duplicates against incoming identity: %s (user: %s, device: %s)", lkIdentity, userInfo.Sub, sfuAccessRequest.DeviceID)

				blockSameDevice := os.Getenv("LIVEKIT_BLOCK_SAME_DEVICE_DUPLICATE") == "true"
				blockSameUserMultiDevice := os.Getenv("LIVEKIT_BLOCK_SAME_USER_MULTIPLE_DEVICES") == "true"

				for _, participant := range participants.Participants {
					// Extract user ID and device ID from participant identity (format: userID:deviceID)
					parts := strings.Split(participant.Identity, ":")
					if len(parts) >= 2 {
						participantUserID := strings.Join(parts[:len(parts)-1], ":") // Everything except last part
						participantDeviceID := parts[len(parts)-1]                   // Last part is device ID

						// Check for same device duplicate
						if blockSameDevice && participantDeviceID == sfuAccessRequest.DeviceID {
							debugLog("Duplicate device session detected - device %s already in room %s (identity: %s)", sfuAccessRequest.DeviceID, sfuAccessRequest.Room, participant.Identity)
							h.writeErrorResponse(w, http.StatusConflict, "M_DUPLICATE_SESSION", "This device is already in the room")
							return
						}

						// Check for same user with multiple devices
						if blockSameUserMultiDevice && participantUserID == userInfo.Sub {
							debugLog("Multiple device session detected - user %s already in room %s with device %s, trying to join with %s", userInfo.Sub, sfuAccessRequest.Room, participantDeviceID, sfuAccessRequest.DeviceID)
							h.writeErrorResponse(w, http.StatusConflict, "M_DUPLICATE_SESSION", "User already in room with another device")
							return
						}
					}
				}
			}
			debugLog("No duplicate session found - proceeding with join")
		}

		token, err := getJoinToken(h.key, h.secret, sfuAccessRequest.Room, lkIdentity, isFullAccessUser)
		if err != nil {
			h.writeErrorResponse(w, http.StatusInternalServerError, "M_UNKNOWN", "Internal Server Error")
			return
		}

		if isFullAccessUser {
			debugLog("Full access user - attempting room creation for: %s", sfuAccessRequest.Room)
			creationStart := time.Now().Unix()
			debugLog("Using existing LiveKit connection to: %s", h.lkUrl)
			createCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			room, err := h.roomClient.CreateRoom(
				createCtx, &livekit.CreateRoomRequest{
					Name:             sfuAccessRequest.Room,
					EmptyTimeout:     5 * 60, // 5 Minutes to keep the room open if no one joins
					DepartureTimeout: 20,     // number of seconds to keep the room after everyone leaves
					MaxParticipants:  0,      // 0 == no limitation
				},
			)

			if err != nil {
				debugLog("Room creation failed, attempting client reconnection: %v", err)
				// Recreate client and retry once
				h.roomClient = lksdk.NewRoomServiceClient(h.lkUrl, h.key, h.secret)
				retryCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				room, err = h.roomClient.CreateRoom(
					retryCtx, &livekit.CreateRoomRequest{
						Name:             sfuAccessRequest.Room,
						EmptyTimeout:     5 * 60,
						DepartureTimeout: 20,
						MaxParticipants:  0,
					},
				)
				if err != nil {
					log.Printf("Unable to create room %s after retry. Error: %v", sfuAccessRequest.Room, err)
					debugLog("Room creation failed for %s after retry: %v", sfuAccessRequest.Room, err)
					h.writeErrorResponse(w, http.StatusInternalServerError, "M_UNKNOWN", "Unable to create room on SFU")
					return
				}
				debugLog("Room creation succeeded after client reconnection")
			}

			// Log the room creation time and the user info
			isNewRoom := room.GetCreationTime() >= creationStart && room.GetCreationTime() <= time.Now().Unix()
			debugLog("Room creation completed - SID: %s, CreationTime: %d, IsNew: %t",
				room.Sid, room.GetCreationTime(), isNewRoom)
			log.Printf(
				"%s LiveKit room sid: %s (alias: %s) for full-access Matrix user %s (LiveKit identity: %s)",
				map[bool]string{true: "Created", false: "Using"}[isNewRoom],
				room.Sid, sfuAccessRequest.Room, userInfo.Sub, lkIdentity,
			)
		} else {
			debugLog("Restricted access user - skipping room creation for: %s", sfuAccessRequest.Room)
		}

		res := SFUResponse{URL: h.lkUrl, JWT: token}
		debugLog("Sending successful response with LiveKit URL: %s", h.lkUrl)

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(res)
		if err != nil {
			log.Printf("failed to encode json response! %v", err)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func main() {
	debugEnabled = os.Getenv("LIVEKIT_DEBUG") == "true"
	if debugEnabled {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Printf("Debug logging enabled")
	}

	// Initialize HTTP client
	skipVerifyTLS := os.Getenv("LIVEKIT_INSECURE_SKIP_VERIFY_TLS") == "YES_I_KNOW_WHAT_I_AM_DOING"
	initHTTPClient(skipVerifyTLS)

	// DEVELOPMENT NOTE: skipVerifyTLS is for development/testing with self-signed certificates only
	if skipVerifyTLS {
		log.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		log.Printf("!!! WARNING !!!  LIVEKIT_INSECURE_SKIP_VERIFY_TLS        !!! WARNING !!!")
		log.Printf("!!! WARNING !!!  Allow to skip invalid TLS certificates  !!! WARNING !!!")
		log.Printf("!!! WARNING !!!  Use only for testing or debugging       !!! WARNING !!!")
		log.Printf("!!! WARNING !!!  NEVER use in production environments    !!! WARNING !!!")
		log.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	}

	key, secret := readKeySecret()
	lkUrl := os.Getenv("LIVEKIT_URL")

	// Check if the key, secret or url are empty.
	if key == "" || secret == "" || lkUrl == "" {
		log.Fatal("LIVEKIT_KEY[_FILE], LIVEKIT_SECRET[_FILE] and LIVEKIT_URL environment variables must be set")
	}

	fullAccessHomeservers := os.Getenv("LIVEKIT_FULL_ACCESS_HOMESERVERS")

	if len(fullAccessHomeservers) == 0 {
		// For backward compatibility we also check for LIVEKIT_LOCAL_HOMESERVERS
		// TODO: Remove this backward compatibility in the near future.
		localHomeservers := os.Getenv("LIVEKIT_LOCAL_HOMESERVERS")
		if len(localHomeservers) > 0 {
			log.Printf("!!! LIVEKIT_LOCAL_HOMESERVERS is deprecated, please use LIVEKIT_FULL_ACCESS_HOMESERVERS instead !!!")
			fullAccessHomeservers = localHomeservers
		} else {
			// If no full access homeservers are set, we default to wildcard '*' to mimic the previous behavior.
			// TODO: Remove defaulting to wildcard '*' (aka full-access for all users) in the near future.
			log.Printf("LIVEKIT_FULL_ACCESS_HOMESERVERS not set, defaulting to wildcard (*) for full access")
			fullAccessHomeservers = "*"
		}
	}

	lkJwtPort := os.Getenv("LIVEKIT_JWT_PORT")
	if lkJwtPort == "" {
		lkJwtPort = "8080"
	}

	log.Printf("LIVEKIT_URL: %s, LIVEKIT_JWT_PORT: %s", lkUrl, lkJwtPort)
	log.Printf("LIVEKIT_FULL_ACCESS_HOMESERVERS: %v", fullAccessHomeservers)

	// Validate configuration for conflicting settings
	allowedHomeservers := os.Getenv("LIVEKIT_ALLOWED_HOMESERVERS")
	blockRestricted := os.Getenv("LIVEKIT_BLOCK_RESTRICTED_HOMESERVERS") == "true"
	if allowedHomeservers != "" && blockRestricted {
		// Check if there are homeservers in allowlist that are not in full access list
		allowedList := strings.Split(allowedHomeservers, ",")
		fullAccessList := strings.Split(fullAccessHomeservers, ",")

		// Clean whitespace
		for i := range allowedList {
			allowedList[i] = strings.TrimSpace(allowedList[i])
		}
		for i := range fullAccessList {
			fullAccessList[i] = strings.TrimSpace(fullAccessList[i])
		}

		// Check for conflicting homeservers
		var conflictingServers []string
		for _, allowed := range allowedList {
			if !slices.Contains(fullAccessList, allowed) && fullAccessHomeservers != "*" {
				conflictingServers = append(conflictingServers, allowed)
			}
		}

		if len(conflictingServers) > 0 {
			log.Printf("CONFIGURATION ERROR: Conflicting settings detected!")
			log.Printf("   LIVEKIT_ALLOWED_HOMESERVERS includes: %v", conflictingServers)
			log.Printf("   But LIVEKIT_BLOCK_RESTRICTED_HOMESERVERS=true will block them")
			log.Printf("   These homeservers are allowed but will be blocked because they're not in LIVEKIT_FULL_ACCESS_HOMESERVERS")
			log.Printf("")
			log.Printf("SOLUTION: Choose one approach:")
			log.Printf("   1. Remove LIVEKIT_BLOCK_RESTRICTED_HOMESERVERS (allow controlled federation)")
			log.Printf("   2. Remove conflicting homeservers from LIVEKIT_ALLOWED_HOMESERVERS (private deployment)")
			log.Printf("   3. Add conflicting homeservers to LIVEKIT_FULL_ACCESS_HOMESERVERS (full trust)")
			log.Fatal("Cannot start with conflicting configuration")
		}
	}

	// Load Ed25519 keys for Matrix verification (if enhanced verification is enabled)
	var privateKey ed25519.PrivateKey
	var synapsePublicKey ed25519.PublicKey
	verificationMethod := os.Getenv("MATRIX_VERIFICATION_METHOD")
	if verificationMethod == "v2" {
		var err error
		privateKey, synapsePublicKey, err = loadEd25519Keys()
		if err != nil {
			log.Printf("Error: Ed25519 keys required for verification method %s: %v", verificationMethod, err)
			log.Fatal("Cannot start with enhanced verification enabled but keys missing")
		}
		log.Printf("Matrix verification method: %s", verificationMethod)

		// Test verification on startup if requested (v2 only - requires keys)
		if os.Getenv("MATRIX_VERIFICATION_TEST_ON_START") == "true" {
			log.Printf("Testing Matrix verification method %s on startup...", verificationMethod)
			testServer := os.Getenv("MATRIX_TEST_SERVER")
			if testServer == "" {
				// Use first full access homeserver as test server
				fullAccessList := strings.Split(fullAccessHomeservers, ",")
				if len(fullAccessList) > 0 && fullAccessList[0] != "*" {
					testServer = strings.TrimSpace(fullAccessList[0])
				} else {
					log.Printf("No test server specified and no specific full access homeservers configured")
					return
				}
			}
			if err := verifyIdentity(testServer, privateKey, synapsePublicKey); err != nil {
				log.Printf("Verification method %s test FAILED: %v", verificationMethod, err)
				if debugEnabled {
					log.Printf("[DEBUG] Test server: %s", testServer)
					log.Printf("[DEBUG] Private key length: %d bytes", len(privateKey))
					log.Printf("[DEBUG] Synapse public key length: %d bytes", len(synapsePublicKey))
				}
				log.Printf("Service will continue but enhanced verification may not work")
			} else {
				log.Printf("Verification method %s test PASSED", verificationMethod)
			}
		}
	} else if verificationMethod == "v1" {
		log.Printf("Matrix verification method: %s (identical to standard federation)", verificationMethod)
	} else {
		log.Printf("Matrix verification: standard federation (no enhanced verification)")
	}

	// Pre-split and cache allowed homeservers list
	var allowedList []string
	if allowedHomeservers != "" {
		allowedList = strings.Split(allowedHomeservers, ",")
		for i := range allowedList {
			allowedList[i] = strings.TrimSpace(allowedList[i])
		}
	}

	// Pre-split and cache blocked homeservers list
	blockedHomeservers := os.Getenv("LIVEKIT_BLOCKED_HOMESERVERS")
	var blockedList []string
	if blockedHomeservers != "" {
		blockedList = strings.Split(blockedHomeservers, ",")
		for i := range blockedList {
			blockedList[i] = strings.TrimSpace(blockedList[i])
		}

		// Check for redundant configuration when allowlist exists
		if len(allowedList) > 0 {
			log.Printf("CONFIGURATION WARNING: LIVEKIT_BLOCKED_HOMESERVERS is redundant when LIVEKIT_ALLOWED_HOMESERVERS is set")
			log.Printf("   LIVEKIT_ALLOWED_HOMESERVERS already blocks all homeservers not in the allowlist")
			log.Printf("   Consider removing LIVEKIT_BLOCKED_HOMESERVERS for cleaner configuration")
		}

		// Check for overlaps with allowed homeservers
		if len(allowedList) > 0 {
			for _, blocked := range blockedList {
				if slices.Contains(allowedList, blocked) {
					log.Printf("CONFIGURATION ERROR: Homeserver '%s' is in both LIVEKIT_ALLOWED_HOMESERVERS and LIVEKIT_BLOCKED_HOMESERVERS", blocked)
					log.Fatal("Cannot start with conflicting homeserver configuration")
				}
			}
			// Check for redundant blocked homeservers when allowlist is active
			if len(blockedList) > 0 {
				log.Printf("   CONFIGURATION WARNING: LIVEKIT_BLOCKED_HOMESERVERS is redundant when LIVEKIT_ALLOWED_HOMESERVERS is set")
				log.Printf("   LIVEKIT_ALLOWED_HOMESERVERS already blocks all homeservers not in the allowlist")
				log.Printf("   Consider removing LIVEKIT_BLOCKED_HOMESERVERS for cleaner configuration")
			}
		}

		// Check for overlaps with full access homeservers
		fullAccessList := strings.Split(fullAccessHomeservers, ",")
		for i := range fullAccessList {
			fullAccessList[i] = strings.TrimSpace(fullAccessList[i])
		}
		for _, blocked := range blockedList {
			if slices.Contains(fullAccessList, blocked) && fullAccessHomeservers != "*" {
				log.Printf(" CONFIGURATION ERROR: Homeserver '%s' is in both LIVEKIT_FULL_ACCESS_HOMESERVERS and LIVEKIT_BLOCKED_HOMESERVERS", blocked)
				log.Fatal("Cannot start with conflicting homeserver configuration")
			}
		}
	}

	// Initialize LiveKit room client once
	roomClient := lksdk.NewRoomServiceClient(lkUrl, key, secret)

	handler := &Handler{
		key:                   key,
		secret:                secret,
		lkUrl:                 lkUrl,
		skipVerifyTLS:         skipVerifyTLS,
		fullAccessHomeservers: strings.Split(fullAccessHomeservers, ","),
		allowedHomeservers:    allowedList,
		blockedHomeservers:    blockedList,
		privateKey:            privateKey,
		synapsePublicKey:      synapsePublicKey,
		roomClient:            roomClient,
	}

	// SECURITY FIX: Set server-level limits to prevent memory exhaustion and slow attacks
	server := &http.Server{
		Addr:              fmt.Sprintf(":%s", lkJwtPort),
		Handler:           handler.prepareMux(),
		MaxHeaderBytes:    8192,            // 8KB header limit
		ReadTimeout:       3 * time.Second, // 3s timeout prevents slow-read attacks
		ReadHeaderTimeout: 2 * time.Second, // 2s timeout for header reading specifically
		WriteTimeout:      3 * time.Second, // 3s timeout prevents slow-write attacks
		IdleTimeout:       5 * time.Second, // Close idle client connections quickly
	}

	log.Fatal(server.ListenAndServe())
}
func (h *Handler) getUserInfoViaIdentityVerify(token OpenIDTokenType, deviceID string, isPublicFacing bool) (*UserInfo, error) {
	debugLog("Getting user info via homeserver /identity/verify endpoint")

	// Validate server name if public-facing
	if err := validateMatrixServerName(token.MatrixServerName, isPublicFacing); err != nil {
		return nil, fmt.Errorf("invalid matrix server name: %v", err)
	}

	// Generate nonce first to handle errors properly
	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("nonce generation failed: %v", err)
	}

	// Create signed payload with access token and device ID
	payload := IdentityPayload{
		SessionID:   uuid.New().String(),
		Timestamp:   time.Now().UnixMilli(),
		Nonce:       nonce,
		AccessToken: token.AccessToken,
		DeviceID:    deviceID, // Include device ID for validation
	}

	// Sign the payload
	signature, err := signPayload(payload, h.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %v", err)
	}

	request := IdentityRequest{
		Payload:   payload,
		Signature: signature,
	}

	// Call homeserver's /identity/verify endpoint
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal identity request: %v", err)
	}
	// SECURITY FIX: Use url.URL for consistent URL construction (aligned with federation path)
	u := &url.URL{
		Scheme: "https",
		Host:   token.MatrixServerName,
		Path:   "/_matrix/client/r0/identity/verify",
	}

	debugLog("Calling homeserver identity verify endpoint: %s", u.String())
	debugLog("Payload includes access_token: %s", payload.AccessToken[:min(20, len(payload.AccessToken))])
	debugLog("Request body: %s", string(reqBody))

	// Create context with deadline aligned to server write timeout (3s)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("internal identity verify call failed: %v", err)
	}
	defer resp.Body.Close()

	// Limit response headers to 100 (5x observed ~20 headers)
	if len(resp.Header) > 100 {
		return nil, fmt.Errorf("too many response headers: %d", len(resp.Header))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity verify returned status %d", resp.StatusCode)
	}

	// Limit response body size to 10KB (5x observed ~2KB)
	dec := json.NewDecoder(io.LimitReader(resp.Body, 10240))
	var response IdentityResponse
	if err := dec.Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode identity verify response: %v", err)
	}

	// Check timestamp within tolerance to prevent replay attacks
	currentTime := time.Now().UnixMilli()
	timeDiff := currentTime - response.Payload.Timestamp
	debugLog("Timestamp validation - Current: %d, Response: %d, Diff: %d ms", currentTime, response.Payload.Timestamp, timeDiff)
	if timeDiff < -TimestampToleranceMs || timeDiff > TimestampToleranceMs {
		debugLog("Timestamp out of range: %d ms (allowed: ±%d ms)", timeDiff, TimestampToleranceMs)
		return nil, fmt.Errorf("timestamp out of range: %d ms", timeDiff)
	}
	debugLog("Timestamp validation passed")

	// Verify session ID and nonce match
	if response.Payload.SessionID != payload.SessionID {
		return nil, fmt.Errorf("session ID mismatch: got %s, expected %s", response.Payload.SessionID, payload.SessionID)
	}
	if response.Payload.Nonce != payload.Nonce {
		return nil, fmt.Errorf("nonce mismatch: got %s, expected %s", response.Payload.Nonce, payload.Nonce)
	}
	debugLog("Session ID and nonce validation passed")

	// Verify response signature
	if err := verifySignature(response.Payload, response.Signature, h.synapsePublicKey); err != nil {
		return nil, fmt.Errorf("identity verify response signature invalid: %v", err)
	}
	debugLog("Response signature verification passed")

	// Extract user info from response
	if response.Payload.UserInfo == nil {
		return nil, fmt.Errorf("no user info in identity verify response")
	}

	sub, ok := response.Payload.UserInfo["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user info format")
	}

	// Validate device if device_validity is present
	if response.Payload.DeviceValidity != "" {
		if response.Payload.DeviceValidity != "valid" {
			debugLog("Device validation failed: %s - dropping call", response.Payload.DeviceValidity)
			return nil, fmt.Errorf("device validation failed: %s", response.Payload.DeviceValidity)
		}
		debugLog("Device validation passed: %s", response.Payload.DeviceValidity)
	}

	debugLog("Successfully got user info via identity verify: %s", sub)
	return &UserInfo{Sub: sub}, nil
}
