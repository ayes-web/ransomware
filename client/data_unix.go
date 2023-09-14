//go:build unix

package main

import (
	"bytes"
	"encoding/gob"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const dataPath = "~/.config/kittens"
const fileName = "data"

func (s *State) SaveData() (err error) {
	var home string
	home, err = os.UserHomeDir()
	if err != nil {
		return
	}

	path := strings.ReplaceAll(dataPath, "~", home)
	fullfile := filepath.Join(path, fileName)

	if err = os.MkdirAll(path, 0777); err != nil {
		return
	}

	var bs bytes.Buffer
	if err := gob.NewEncoder(&bs).Encode(s); err != nil {
		log.Fatal("encode error:", err)
	}

	err = os.WriteFile(fullfile, bs.Bytes(), 0777)
	return
}

func LoadData() (s State, err error) {
	var home string
	home, err = os.UserHomeDir()
	if err != nil {
		return
	}

	path := strings.ReplaceAll(dataPath, "~", home)
	if _, err = os.Stat(path); os.IsNotExist(err) {
		return
	} else if err != nil {
		return
	}

	var bs []byte
	bs, err = os.ReadFile(filepath.Join(path, fileName))
	if err != nil {
		return
	}

	err = gob.NewDecoder(bytes.NewBuffer(bs)).Decode(&s)

	return
}

func DeleteData() (err error) {
	var home string
	home, err = os.UserHomeDir()
	if err != nil {
		return
	}

	path := strings.ReplaceAll(dataPath, "~", home)
	if _, err = os.Stat(path); os.IsNotExist(err) {
		return
	} else if err != nil {
		return
	}

	err = os.RemoveAll(path)
	return
}
