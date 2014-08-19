cryptosigner
============

Signs cryptocurrency transactions (btc, ltc, etc.) provided a pre-defined target address. Generalizable to any type of challenge before signature.

The cryptosigner is a small https server that works in the following way:

  * A first call (/transfer) requests a source address for transfer to a provided target address. A private key for the source is generated and encrypted and will only be used to sign transactions to the target address.
  * A second call (/sign) expects a raw hex transaction ready to be hashed and signed. The output of the transaction will be checked and has to send to the previously provided target. If accepted, the transaction will be signed using the private key previously generated.

Usage
-----
```shell
$ go test
$ go build
$ ./cryptosigner
```

Before running, SSL certificate and key are expected to be found in the current directory. 
```shell
$ curl -k -d "targetAddr=15qx9ug952GWGTNn7Uiv6vode4RcGrRemh" https://localhost:8443/transfer
1QHFuxSudUgnvPAf34CzBhWm9nG6g3DAGn

$ curl -k -d "sourceAddr=1QHFuxSudUgnvPAf34CzBhWm9nG6g3DAGn&data=0100000..." https://localhost:8443/sign
3045022100d52...
```

Each HTTP endpoint expects the data to be form-encoded. Binary data in inputs and outputs is hex-encoded.

Security
--------
To secure transactions and private keys, the cryptosigner works in the following way:

  * Requires a password to start (wrap with stty to disable output).
  * Password is immediately hashed and never held in memory.
  * An AES cipher is derived from the password hash to encrypt all generated private keys.
  * Private keys are generated locally and immediately encrypted.
  * Private keys are never stored unencrypted.
  * Private keys are held in memory only for a very brief period of time (microseconds) when they're generated and when they're needed to sign a transaction.
  * When generated, private keys are associated with a challenge. Before decrypting the private key, the data to be signed need to check against the challenge. If the challenge isn't statisfied, the data is not signed.
  * The default challenge is an output public key check. This guarantees that transactions will only be signed if they target a pre-defined address (preventing sending to an attacker's key).

To avoid possible rootkit+keylogger attacks on the password if the machine the cryptosigner runs on is compromised, it's recommended to always start the cryptosigner on a brand new, remastered OS.
