package ldapaggregator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCrypto(t *testing.T) {
	c, err := NewCrypto("my-key")
	assert.NoError(t, err)
	p := "adm!in-password#1$"
	ep, err := c.EncryptPassword(p)
	assert.NoError(t, err)
	assert.NotEqual(t, p, string(ep))
	dp, err := c.DecryptPassword(ep)
	assert.NoError(t, err)
	assert.Equal(t, p, dp)
}

func TestCryptoEncryptPasswordDifferentPassphrase(t *testing.T) {
	c, err := NewCrypto("my-key")
	assert.NoError(t, err)
	p := "adm!in-password#1$"
	ep, err := c.EncryptPassword(p)
	assert.NoError(t, err)
	c2, err := NewCrypto("other-key")
	assert.NoError(t, err)
	ep2, err := c2.EncryptPassword(p)
	assert.NoError(t, err)
	assert.NotEqual(t, ep, ep2)
	dp, err := c2.DecryptPassword(ep2)
	assert.NoError(t, err)
	assert.Equal(t, dp, p)
	_, err = c2.DecryptPassword(ep)
	assert.Error(t, err)
}
