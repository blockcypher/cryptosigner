package signer

import (
  "io/ioutil"
  "log"
  "os"
  "path"
)

const (
  DIRNAME = ".store"
)

type Store interface {
  Save(key string, data []byte) error
  Delete(key string) error
  ReadAll() ([][]byte, error)
}

// Saves key data in files under a given directory
type FileStore struct {
}

func MakeFileStore() (*FileStore, error) {
  err := os.MkdirAll(DIRNAME, 0700)
  if err != nil { return nil, err }
  return &FileStore{}, nil
}

func (self *FileStore) ReadAll() ([][]byte, error) {
  log.Println("reading dir")
  files, err := ioutil.ReadDir(DIRNAME)
  if err != nil { return nil, err }
  data := make([][]byte, 0, len(files))
  log.Println("going to scan files dir")
  for n, f := range files {
    if f.IsDir() { continue }
    if n % 1000 == 0 { log.Println(n) }
    content, err := ioutil.ReadFile(path.Join(DIRNAME, f.Name()))
    if err != nil { return nil, err }
    data = append(data, content)
  }
  log.Println("done reading")
  return data, nil
}

func (self *FileStore) Save(key string, data []byte) error {
  return ioutil.WriteFile(path.Join(DIRNAME, key), data, 0600)
}

func (self *FileStore) Delete(key string) error {
  return os.Remove(path.Join(DIRNAME, key))
}

// Test-only in-memory key store
type TestStore struct {
  store map[string][]byte
}

func MakeTestStore() *TestStore {
  return &TestStore{make(map[string][]byte)}
}

func (self *TestStore) ReadAll() ([][]byte, error) {
  values := make([][]byte, 0, len(self.store))
  for _, value := range self.store {
    values = append(values, value)
  }
  return values, nil
}

func (self *TestStore) Save(key string, data []byte) error {
  self.store[key] = data
  return nil
}

func (self *TestStore) Delete(key string) error {
  delete(self.store, key)
  return nil
}
