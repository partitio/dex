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
