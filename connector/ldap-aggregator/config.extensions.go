package ldapaggregator

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/jsonpb"
)

var crypto PasswordCrypto

func (c *LdapConfig) AfterToORM(ctx context.Context, conf *LdapConfigORM) error {
	if conf.Id == "" {
		conf.Id = c.Host
	}
	if len(c.BindPW) == 0 {
		return nil
	}
	pw, err := crypto.EncryptPassword(c.BindPW)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %v", err)
	}
	conf.BindPW = pw
	return nil
}

func (c *LdapConfigORM) AfterToPB(ctx context.Context, conf *LdapConfig) error {
	if len(c.BindPW) == 0 {
		return nil
	}
	pw, err := crypto.DecryptPassword(c.BindPW)
	if err != nil {
		return fmt.Errorf("failed to decrypt password: %v", err)
	}
	conf.BindPW = pw
	return nil
}

func (c *LdapConfig) UnmarshalJSON(b []byte) error {
	return jsonpb.UnmarshalString(string(b), c)
}
