package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// sshsign is the git signing CLI wrapper.
//
// Git invokes it as:
//   sshsign -Y sign -f <key_file> -n git < payload
//
// It SSHs to the sshsign server, sends the payload via the "sign" command,
// and outputs the PEM-armored SSH signature to stdout.

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	var operation, namespace, keyFile string
	var sigFile, allowedSigners, identity string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-Y":
			if i+1 < len(args) {
				operation = args[i+1]
				i++
			}
		case "-n":
			if i+1 < len(args) {
				namespace = args[i+1]
				i++
			}
		case "-f":
			if i+1 < len(args) {
				keyFile = args[i+1]
				i++
			}
		case "-s":
			if i+1 < len(args) {
				sigFile = args[i+1]
				i++
			}
		case "-I":
			if i+1 < len(args) {
				identity = args[i+1]
				i++
			}
		}
	}

	_ = keyFile       // Ignored: server looks up key by user.signingkey
	_ = allowedSigners
	_ = identity

	if namespace == "" {
		namespace = "git"
	}

	switch strings.ToLower(operation) {
	case "sign":
		handleSign(namespace)
	case "verify":
		handleVerify(namespace, sigFile)
	default:
		fmt.Fprintf(os.Stderr, "sshsign: unsupported operation: %s\n", operation)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "sshsign - SSH signing service CLI for sshsign")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Git integration:")
	fmt.Fprintln(os.Stderr, "  git config --global gpg.format ssh")
	fmt.Fprintln(os.Stderr, "  git config --global gpg.ssh.program sshsign")
	fmt.Fprintln(os.Stderr, "  git config --global user.signingkey <key_id>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Environment:")
	fmt.Fprintln(os.Stderr, "  SSHSIGN_HOST  Server host (default: sign.agenticpoa.com)")
	fmt.Fprintln(os.Stderr, "  SSHSIGN_PORT  Server port (default: 22)")
	fmt.Fprintln(os.Stderr, "  SSHSIGN_KEY   Signing key ID (default: from user.signingkey)")
}

func handleSign(namespace string) {
	payload, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("reading stdin: %v", err)
	}

	host := envOrDefault("SSHSIGN_HOST", "sign.agenticpoa.com")
	port := envOrDefault("SSHSIGN_PORT", "22")
	keyID := os.Getenv("SSHSIGN_KEY")

	sshConfig := buildSSHConfig()

	addr := net.JoinHostPort(host, port)
	client, err := gossh.Dial("tcp", addr, sshConfig)
	if err != nil {
		fatal("connecting to %s: %v", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		fatal("creating session: %v", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(payload)

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	cmd := "sign --type git-commit"
	if keyID != "" {
		cmd += " --key-id " + keyID
	}

	if err := session.Run(cmd); err != nil {
		fatal("sign command failed: %v\nstderr: %s", err, stderr.String())
	}

	// Parse the JSON response and extract the signature
	var resp struct {
		Signature string `json:"signature"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		fatal("parsing response: %v\nraw: %s", err, stdout.String())
	}
	if resp.Error != "" {
		fatal("server error: %s", resp.Error)
	}

	// Output the PEM-armored signature (what git expects)
	fmt.Print(resp.Signature)
}

func handleVerify(namespace, sigFile string) {
	// For verification, read the signature file and payload from stdin
	payload, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("reading stdin: %v", err)
	}

	sigData, err := os.ReadFile(sigFile)
	if err != nil {
		fatal("reading signature file: %v", err)
	}

	host := envOrDefault("SSHSIGN_HOST", "sign.agenticpoa.com")
	port := envOrDefault("SSHSIGN_PORT", "22")

	sshConfig := buildSSHConfig()

	addr := net.JoinHostPort(host, port)
	client, err := gossh.Dial("tcp", addr, sshConfig)
	if err != nil {
		fatal("connecting to %s: %v", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		fatal("creating session: %v", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(payload)

	var stdout bytes.Buffer
	session.Stdout = &stdout

	cmd := fmt.Sprintf("verify --signature %s", string(sigData))
	if err := session.Run(cmd); err != nil {
		os.Exit(1)
	}

	var resp struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	json.Unmarshal(stdout.Bytes(), &resp)
	if !resp.Valid {
		os.Exit(1)
	}
}

func buildSSHConfig() *gossh.ClientConfig {
	var authMethods []gossh.AuthMethod

	// Try SSH agent first
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			agentClient := agent.NewClient(conn)
			authMethods = append(authMethods, gossh.PublicKeysCallback(agentClient.Signers))
		}
	}

	// Try default SSH key locations
	home, _ := os.UserHomeDir()
	keyPaths := []string{
		home + "/.ssh/id_ed25519",
		home + "/.ssh/id_rsa",
		home + "/.ssh/id_ecdsa",
	}
	for _, path := range keyPaths {
		key, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		signer, err := gossh.ParsePrivateKey(key)
		if err != nil {
			continue
		}
		authMethods = append(authMethods, gossh.PublicKeys(signer))
	}

	return &gossh.ClientConfig{
		User:            os.Getenv("USER"),
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), // TODO: pin host key in production
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sshsign: "+format+"\n", args...)
	os.Exit(1)
}
