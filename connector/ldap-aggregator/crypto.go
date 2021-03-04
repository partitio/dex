package ldapaggregator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

type PasswordCrypto interface {
	EncryptPassword(pass string) ([]byte, error)
	DecryptPassword(pass []byte) (string, error)
}

type Crypto struct {
	key string
}

func NewCrypto(key string) (PasswordCrypto, error) {
	if key == "" {
		return nil, errors.New("key cannot be empty")
	}
	return &Crypto{key}, nil
}

func (c *Crypto) EncryptPassword(pass string) ([]byte, error) {
	return c.encrypt([]byte(pass))
}

func (c *Crypto) DecryptPassword(pass []byte) (string, error) {
	b, err := c.decrypt(pass)
	return string(b), err
}

func (c *Crypto) createHash() string {
	hasher := md5.New()
	hasher.Write([]byte(c.key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (c *Crypto) encryptString(data string) (string, error) {
	s, err := c.encrypt([]byte(data))
	return string(s), err
}

func (c *Crypto) encrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(c.createHash()))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (c *Crypto) decryptString(data string) (string, error) {
	s, err := c.decrypt([]byte(data))
	return string(s), err
}

func (c *Crypto) decrypt(data []byte) ([]byte, error) {
	// out := data
	key := []byte(c.createHash())
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	b := data
	nonce, ciphertext := b[:nonceSize], b[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
	// return plaintext, nil
}
