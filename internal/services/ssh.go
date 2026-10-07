package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const sshServerVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

// loadOrCreateHostKey returns a persistent ed25519 SSH host key so scanners that
// fingerprint hosts see a stable identity across restarts.
func loadOrCreateHostKey(dir string) (ssh.Signer, error) {
	if dir == "" {
		dir = "."
	}
	path := filepath.Join(dir, "ssh_host_ed25519_key")
	if data, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(data); blk != nil {
			if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
				return ssh.NewSignerFromKey(k)
			}
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if der, err := x509.MarshalPKCS8PrivateKey(priv); err == nil {
		_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	}
	return ssh.NewSignerFromKey(priv)
}

type sshAttempt struct {
	user, method, secret string
}

// sshHandler runs a real SSH key exchange and authentication exchange against
// the client but never grants access, recording every password and public key
// the client offers.
func (e *Env) sshHandler() (ConnHandler, error) {
	signer, err := loadOrCreateHostKey(e.DataDir)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, c net.Conn, srcIP string) Result {
		var attempts []sshAttempt
		cfg := &ssh.ServerConfig{
			ServerVersion: sshServerVersion,
			MaxAuthTries:  6,
			PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
				attempts = append(attempts, sshAttempt{m.User(), "password", string(pw)})
				return nil, errors.New("permission denied")
			},
			PublicKeyCallback: func(m ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				attempts = append(attempts, sshAttempt{m.User(), "publickey", ssh.FingerprintSHA256(key)})
				return nil, errors.New("permission denied")
			},
			KeyboardInteractiveCallback: func(m ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				ans, err := ch(m.User(), "", []string{"Password: "}, []bool{false})
				if err == nil && len(ans) > 0 {
					attempts = append(attempts, sshAttempt{m.User(), "keyboard-interactive", ans[0]})
				}
				return nil, errors.New("permission denied")
			},
		}
		cfg.AddHostKey(signer)

		var clientVersion string
		conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
		if err == nil { // cannot happen (no callback accepts) but never leak
			clientVersion = string(conn.ClientVersion())
			conn.Close()
			go ssh.DiscardRequests(reqs)
			_ = chans
		}
		return sshResult(c, clientVersion, attempts)
	}, nil
}

func sshResult(c net.Conn, clientVersion string, attempts []sshAttempt) Result {
	meta := map[string]string{}
	if clientVersion != "" {
		meta["ssh_client"] = clientVersion
	}
	res := Result{Meta: meta, Detail: "ssh connection, no authentication attempted"}
	if len(attempts) == 0 {
		return res
	}
	meta["user"] = attempts[0].user
	meta["auth_method"] = attempts[0].method
	meta["attempts"] = fmt.Sprint(len(attempts))
	var parts []string
	var tags []string
	for i, a := range attempts {
		if i == 0 {
			meta["secret"] = a.secret
		}
		if i < 3 {
			if a.method == "password" {
				parts = append(parts, a.user+":"+a.secret)
			} else {
				parts = append(parts, a.user+" key "+a.secret)
			}
		}
		if a.method == "password" {
			tags = append(tags, ClassifyCreds(a.user, a.secret)...)
		}
	}
	more := ""
	if len(attempts) > 3 {
		more = fmt.Sprintf(" (+%d more)", len(attempts)-3)
	}
	res.Detail = "ssh login " + strings.Join(parts, ", ") + more
	res.Tags = mergeTags(tags, []string{"credential-attempt"})
	return res
}
