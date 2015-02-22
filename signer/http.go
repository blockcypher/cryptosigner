package signer

import (
  "encoding/hex"
  "log"
  "net/http"
  "strconv"
)

type SigningHandler struct {
  hold *Hold
}

func (self *SigningHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  if r.Method == "POST" {
    err := r.ParseForm()
    if err != nil { r400(w, "Invalid form data."); return }

    switch r.URL.Path {
    case "/transfer":
      targetAddr  := r.FormValue("targetAddr")
      feeAddr     := r.FormValue("feeAddr")
      prefixVal   := r.FormValue("prefix")
      if len(targetAddr) == 0 { r400(w, "Missing target address for transfer."); return }

      prefix := byte(0)
      if len(prefixVal) > 0 {
        preint, err := strconv.Atoi(prefixVal)
        if err != nil { r400(w, "Invalid prefix."); return }
        prefix = byte(preint)
      }
      addrs := []string{targetAddr}
      if len(feeAddr) > 0 { addrs = append(addrs, feeAddr) }
      log.Println(addrs)

      addr, err := self.hold.NewKey(NewSignatureChallenge(addrs), prefix)
      if err != nil { r500(w, err); return }
      log.Println("transfer |", addr, "->", targetAddr)
      w.Write([]byte(addr))
      return

    case "/sign":
      sourceAddr  := r.FormValue("sourceAddr")
      txDataStr   := r.FormValue("txData")
      if len(sourceAddr) == 0 || len(txDataStr) == 0 {
        r400(w, "Missing source address or tx data to sign.")
        return
      }
      log.Println("sign     |", sourceAddr)

      txData, err := hex.DecodeString(txDataStr)
      if err != nil { r400(w, "Bad hex encoding."); return }

      sig, pubkey, err := self.hold.Sign(sourceAddr, txData)
      if err != nil { r500(w, err); return }
      w.Write([]byte(hex.EncodeToString(sig)+"|"+hex.EncodeToString(pubkey)))
      log.Println("sign     | ok")
      return
    }
  }
  w.WriteHeader(404)
}

func StartServer(hold *Hold) {
  httpServer  := &http.Server{
      Addr    : ":8443",
      Handler : &SigningHandler{hold},
  }

  log.Println("Server started.")
  log.Fatal(httpServer.ListenAndServeTLS("signer.crt", "signer.key"))
}

func r400(w http.ResponseWriter, msg string) {
  w.WriteHeader(400)
  w.Write([]byte(msg))
}

func r500(w http.ResponseWriter, err error) {
  w.WriteHeader(500)
  w.Write([]byte(err.Error()))
}
