package main

import (
	"fmt"
	"log"

	"github.com/blockcypher/cryptosigner/signer"
	"github.com/blockcypher/cryptosigner/util"
)

func main() {
	fmt.Print("Enter password: ")
	var pwd string
	fmt.Scanln(&pwd)
	if len(pwd) == 0 {
		log.Fatal("Could not read.")
	}

	ecdsaSigner := &util.ECDSASigner{}
	store, err := signer.MakeFileStore()
	if err != nil {
		log.Println(err)
		return
	}

	hold, err := signer.MakeHold(pwd, store, ecdsaSigner)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Starting server")
	signer.StartServer(hold)
}
