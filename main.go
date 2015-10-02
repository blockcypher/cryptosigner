package main

import (
	"fmt"
	. "github.com/blockcypher/cryptosigner/signer"
	"log"
)

func main() {
	fmt.Print("Enter password: ")
	var pwd string
	fmt.Scanln(&pwd)
	if len(pwd) == 0 {
		log.Fatal("Could not read.")
	}

	signer := &ECDSASigner{}
	store, err := MakeFileStore()
	if err != nil {
		log.Println(err)
		return
	}

	hold, err := MakeHold(pwd, store, signer)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Starting server")
	StartServer(hold)
}
