//go:build windows

package main

import (
	"bytes"
	"encoding/gob"
	"log"

	"golang.org/x/sys/windows/registry"
)

const registryKey = `SOFTWARE\Kitty\kittens\data`
const registryField = "meow"

const registryPerms = registry.QUERY_VALUE | registry.SET_VALUE

func (s *State) SaveData() (err error) {
	var k registry.Key
	k, _, err = registry.CreateKey(registry.CURRENT_USER, registryKey, registryPerms)
	if err != nil {
		return
	}

	defer k.Close()

	var bs bytes.Buffer
	if err := gob.NewEncoder(&bs).Encode(s); err != nil {
		log.Fatal("encode error:", err)
	}

	err = k.SetBinaryValue(registryField, bs.Bytes())
	return
}

func LoadData() (s State, err error) {
	var (
		k       registry.Key
		existed bool
	)
	k, existed, err = registry.CreateKey(registry.CURRENT_USER, registryKey, registryPerms)
	if !existed {
		err = nil
		return
	} else if err != nil {
		return
	}

	defer k.Close()

	var bs []byte
	bs, _, err = k.GetBinaryValue(registryField)
	if err != nil {
		return
	}

	s.Keys = make(map[string][]byte)
	err = gob.NewDecoder(bytes.NewBuffer(bs)).Decode(&s)

	return
}

func DeleteData() (err error) {
	err = registry.DeleteKey(registry.CURRENT_USER, registryKey)
	return
}
