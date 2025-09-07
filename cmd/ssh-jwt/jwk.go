package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"go.ptx.dk/ssh-jwt"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`           // Key Type
	Use string `json:"use,omitempty"` // Public Key Use
	Alg string `json:"alg,omitempty"` // Algorithm
	Kid string `json:"kid,omitempty"` // Key ID
	N   string `json:"n"`             // RSA modulus
	E   string `json:"e"`             // RSA exponent
}

// JWKSet represents a JSON Web Key Set
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func jwkCmd(cmd *cobra.Command, args []string) error {
	// Get the SSH agent connection directly
	agent, err := getAgent()
	if err != nil {
		return err
	}

	// Verify we can access keys
	keys, err := agent.AllKeys()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return fmt.Errorf("no keys found in SSH agent")
	}

	// Since we can't access the private fields directly, let's create a JWK
	// by recreating the SSH client connection and accessing keys
	jwk, err := extractJWKFromAgent()
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}

// Helper function to extract JWK by directly accessing SSH agent
func extractJWKFromAgent() (*JWK, error) {
	// Create a new SSH agent connection similar to getAgent()
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := sshagent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found in SSH agent")
	}

	// Use the first key - parse the agent.Key to get an ssh.PublicKey
	agentKey := keys[0]
	pubKey, err := ssh.ParsePublicKey(agentKey.Blob)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	
	// Use the comment from the SSH agent key for a more descriptive key ID
	// But allow override with the --key-id flag
	var keyComment string
	if jwkKeyID != "" {
		keyComment = jwkKeyID
	} else {
		keyComment = agentKey.Comment
	}
	
	return sshPublicKeyToJWK(pubKey, keyComment)
}

func sshPublicKeyToJWK(pubKey ssh.PublicKey, keyComment string) (*JWK, error) {
	// Try to get the crypto public key
	cryptoPublicKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("key does not implement CryptoPublicKey interface")
	}
	
	// Parse the SSH public key to get the underlying crypto key
	cryptoKey := cryptoPublicKey.CryptoPublicKey()
	
	rsaKey, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only RSA keys are supported, got %T", cryptoKey)
	}

	// Generate key ID from SSH key comment if available, otherwise use hash
	keyID := generateKeyIDFromComment(keyComment, pubKey)

	// Convert RSA key to JWK format
	jwk := &JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: sshjwt.SSHSigningMethod.Alg(), // Use the same algorithm as the signer
		Kid: keyID,
		N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}

	return jwk, nil
}

func generateKeyIDFromComment(keyComment string, pubKey ssh.PublicKey) string {
	if keyComment != "" {
		// Use the comment directly as key ID if provided (via --key-id flag or SSH comment)
		return keyComment
	}
	
	// Fallback to hash-based ID if no comment
	return generateKeyID(pubKey)
}

func generateKeyID(pubKey ssh.PublicKey) string {
	// Generate SHA256 fingerprint similar to SSH fingerprint
	hash := sha256.Sum256(pubKey.Marshal())
	return base64.RawURLEncoding.EncodeToString(hash[:])[:8]
}
