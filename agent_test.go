package sshagent_test

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caarlos0/go-sshagent"
	"github.com/charmbracelet/keygen"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSSHAgent(t *testing.T) {
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Skipf("ssh-add not present in PATH")
	}

	agt := setupAgetnt(t, makeSigner(t), makeSigner(t))
	cmd := exec.Command("ssh-add", "-L")
	cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+agt.Socket())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.Split(strings.TrimSpace(string(out)), "\n")
	if l := len(keys); l != 2 {
		t.Errorf("expected 2 keys, got %d", l)
	}
}

func TestSign(t *testing.T) {
	signer := makeSigner(t)
	agt := setupAgetnt(t, signer)

	t.Run("signers", func(t *testing.T) {
		signers, err := agt.Signers()
		if err != nil {
			t.Fatal(err)
		}
		if l := len(signers); l != 1 {
			t.Errorf("expected 1 keys, got %d", l)
		}
	})

	t.Run("sign with valid key", func(t *testing.T) {
		data := []byte("some data")
		sig, err := agt.Sign(signer.PublicKey(), data)
		if err != nil {
			t.Fatal(err)
		}
		if err := signer.PublicKey().Verify(data, sig); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sign with invalid key", func(t *testing.T) {
		data := []byte("some data")
		_, err := agt.Sign(makeSigner(t).PublicKey(), data)
		if err == nil {
			t.Fatalf("expected an error, got nil")
		}
	})
}

func TestUnsupportedOps(t *testing.T) {
	assertErr := func(tb testing.TB, err error) {
		eerr := sshagent.ErrUnsupportedOperation{}
		if !errors.As(err, &eerr) {
			t.Errorf("expected unsupported operation error, got %v", err)
		}
	}

	agt := sshagent.New(makeSigner(t))

	t.Run("add", func(t *testing.T) {
		assertErr(t, agt.Add(agent.AddedKey{}))
	})
	t.Run("remove", func(t *testing.T) {
		assertErr(t, agt.Remove(nil))
	})
	t.Run("remove all", func(t *testing.T) {
		assertErr(t, agt.RemoveAll())
	})
	t.Run("lock", func(t *testing.T) {
		assertErr(t, agt.Lock(nil))
	})
	t.Run("unlock", func(t *testing.T) {
		assertErr(t, agt.Unlock(nil))
	})

	t.Run("error", func(t *testing.T) {
		err := agt.RemoveAll()
		if err.Error() != "operation not supported: RemoveAll" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func makeSigner(tb testing.TB) ssh.Signer {
	tb.Helper()
	k, err := keygen.New(filepath.Join(tb.TempDir(), "key_ed25519"), keygen.WithKeyType(keygen.Ed25519))
	if err != nil {
		tb.Fatal(err)
	}
	return k.Signer()
}

func setupAgetnt(tb testing.TB, signers ...ssh.Signer) *sshagent.Agent {
	agt := sshagent.New(signers...)
	go func() {
		_ = agt.Start()
	}()

	tb.Cleanup(func() {
		_ = agt.Close()
	})

	for !agt.Ready() {
		time.Sleep(time.Millisecond * 100)
	}

	return agt
}
