package ldapaggregator

import (
	"context"

	"github.com/golang/protobuf/jsonpb"
)

// TODO : encrypt password

func (c *LdapConfig) BeforeToORM(ctx context.Context, conf *LdapConfigORM) error {
	conf.Id = c.Host
	return nil
}

func (c *LdapConfig) AfterToORM(ctx context.Context, conf *LdapConfigORM) error {
	conf.Id = c.Host
	return nil
}

func (c *LdapConfigORM) BeforeToPB(ctx context.Context, conf *LdapConfig) error {
	c.Id = conf.Host
	return nil
}

func (c *LdapConfigORM) AfterToPB(ctx context.Context, conf *LdapConfig) error {
	c.Id = conf.Host
	return nil
}

func (c *LdapConfig) UnmarshalJSON(b []byte) error {
	return jsonpb.UnmarshalString(string(b), c)
}
