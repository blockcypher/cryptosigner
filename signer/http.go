package signer

import (
  "encoding/hex"
  "log"
  "net/http"
  "strconv"
)

func StartServer(hold *Hold) {
  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
      err := r.ParseForm()
      if err != nil { r400(w, "Invalid form data."); return }

      switch r.URL.Path {
      case "/transfer":
        targetAddr  := r.FormValue("targetAddr")
        prefixVal   := r.FormValue("prefix")
        if len(targetAddr) == 0 { r400(w, "Missing target address for transfer."); return }

        prefix := byte(0)
        if len(prefixVal) > 0 {
          preint, err := strconv.Atoi(prefixVal)
          if err != nil { r400(w, "Invalid prefix."); return }
          prefix = byte(preint)
        }

        addr, err := hold.NewKey(NewSignatureChallenge(targetAddr), prefix)
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

        sig, err := hold.Sign(sourceAddr, txData)
        if err != nil { r500(w, err); return }
        w.Write([]byte(hex.EncodeToString(sig)))
        log.Println("sign     | ok")
        return
      }
    }
    w.WriteHeader(404)
  })

  log.Println("Server started.")
  log.Fatal(http.ListenAndServeTLS(":8443", "signer.crt", "signer.key", nil))
}

func r400(w http.ResponseWriter, msg string) {
  w.WriteHeader(400)
  w.Write([]byte(msg))
}

func r500(w http.ResponseWriter, err error) {
  w.WriteHeader(500)
  w.Write([]byte(err.Error()))
}
