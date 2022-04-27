package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caarlos0/go-sshagent"
	"github.com/charmbracelet/keygen"
	"golang.org/x/crypto/ssh"
)

func main() {
	key, err := keygen.New("/tmp/fakekey", nil, keygen.Ed25519)
	if err != nil {
		log.Fatalln(err)
	}

	signer, err := ssh.ParsePrivateKey(key.PrivateKeyPEM())
	if err != nil {
		log.Fatalln(err)
	}

	agt := sshagent.New(signer)
	go func() {
		if err := agt.Start(); err != nil {
			log.Fatalln(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGKILL, syscall.SIGINT)

	for !agt.Ready() {
		time.Sleep(time.Millisecond * 100)
	}

	log.Println("agent listening on", agt.Socket())

	<-c
	if err := agt.Close(); err != nil {
		log.Fatalln(err)
	}
}
