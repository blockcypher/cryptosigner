package signer

import (
	"io/ioutil"
	"log"
	"os"
	"path"
)

// DirName is the storage directory name
const DirName = ".store"

// Store inteface
type Store interface {
	Save(key string, data []byte) error
	Delete(key string) error
	ReadAll() ([][]byte, error)
}

// FileStore saves key data in files under a given directory
type FileStore struct{}

// MakeFileStore creates the file store
func MakeFileStore() (*FileStore, error) {
	err := os.MkdirAll(DirName, 0700)
	if err != nil {
		return nil, err
	}
	return &FileStore{}, nil
}

// ReadAll reads all the data in the file store
func (fs *FileStore) ReadAll() ([][]byte, error) {
	log.Println("reading dir")
	files, err := ioutil.ReadDir(DirName)
	if err != nil {
		return nil, err
	}
	data := make([][]byte, 0, len(files))
	log.Println("going to scan files dir")
	for n, f := range files {
		if f.IsDir() {
			continue
		}
		if n%1000 == 0 {
			log.Println(n)
		}
		content, err := ioutil.ReadFile(path.Join(DirName, f.Name()))
		if err != nil {
			return nil, err
		}
		data = append(data, content)
	}
	log.Println("done reading")
	return data, nil
}

// Save saves data with a key
func (fs *FileStore) Save(key string, data []byte) error {
	return ioutil.WriteFile(path.Join(DirName, key), data, 0600)
}

// Delete deletes some data
func (fs *FileStore) Delete(key string) error {
	return os.Remove(path.Join(DirName, key))
}
