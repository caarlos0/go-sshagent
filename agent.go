// Package sshagent provides an SSH agent implementation that's bootstraped with
// the given signers, which cannot be changed.
//
// It is intended to be used on testing only.
package sshagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// New create a new agent with the given signers.
func New(signers ...ssh.Signer) *Agent {
	return &Agent{
		signers: signers,
	}
}

// Agent is the ssh agent implementation.
type Agent struct {
	signers []ssh.Signer
	close   func() error
	socket  string
}

var _ agent.Agent = &Agent{}

// Start the agent in a random socket.
func (a *Agent) Start() error {
	f, err := os.CreateTemp(os.TempDir(), "agent.*")
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	if err := os.Remove(f.Name()); err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}

	sock := f.Name()
	l, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("failed to start listening: %w", err)
	}

	a.socket = sock
	a.close = l.Close

	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("could not accept request: %w", err)
		}
		if err := agent.ServeAgent(a, c); err != nil && err != io.EOF {
			return fmt.Errorf("could not serve request: %w", err)
		}
	}
}

// Close the agent and cleanup.
func (a *Agent) Close() error {
	return a.close()
}

// Socket returns the unix socket address in which the agent is listening.
func (a *Agent) Socket() string {
	return a.socket
}

// Ready tells whether the agent is ready or not.
func (a *Agent) Ready() bool {
	return a.socket != ""
}

func (a *Agent) List() ([]*agent.Key, error) {
	result := make([]*agent.Key, 0, len(a.signers))
	for _, k := range a.signers {
		result = append(result, &agent.Key{
			Format:  k.PublicKey().Type(),
			Blob:    k.PublicKey().Marshal(),
			Comment: "",
		})
	}
	return result, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	var signer ssh.Signer
	for _, s := range a.signers {
		if bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			signer = s
			break
		}
	}
	if signer == nil {
		return nil, fmt.Errorf("invalid key: %s", ssh.FingerprintSHA256(key))
	}
	return signer.Sign(rand.Reader, data)
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	return a.signers, nil
}

// ErrUnsupportedOperation is returned on operations that are not implemented.
type ErrUnsupportedOperation struct {
	Op string
}

func (e ErrUnsupportedOperation) Error() string {
	return fmt.Sprintf("operation not supported: %s", e.Op)
}

func (a *Agent) Add(key agent.AddedKey) error   { return ErrUnsupportedOperation{"Add"} }
func (a *Agent) Remove(key ssh.PublicKey) error { return ErrUnsupportedOperation{"Remove"} }
func (a *Agent) RemoveAll() error               { return ErrUnsupportedOperation{"RemoveAll"} }
func (a *Agent) Lock(passphrase []byte) error   { return ErrUnsupportedOperation{"Lock"} }
func (a *Agent) Unlock(passphrase []byte) error { return ErrUnsupportedOperation{"Unlock"} }
