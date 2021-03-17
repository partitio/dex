// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: config.proto

package ldapaggregator

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/ptypes"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = ptypes.DynamicAny{}
)

// Validate checks the field values on LdapConfig with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *LdapConfig) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Id

	// no validation rules for Host

	// no validation rules for InsecureNoSSL

	// no validation rules for InsecureSkipVerify

	// no validation rules for StartTLS

	// no validation rules for RootCA

	// no validation rules for ClientCert

	// no validation rules for ClientKey

	// no validation rules for RootCAData

	if utf8.RuneCountInString(m.GetBindDN()) < 3 {
		return LdapConfigValidationError{
			field:  "BindDN",
			reason: "value length must be at least 3 runes",
		}
	}

	if utf8.RuneCountInString(m.GetBindPW()) < 3 {
		return LdapConfigValidationError{
			field:  "BindPW",
			reason: "value length must be at least 3 runes",
		}
	}

	// no validation rules for UsernamePrompt

	// no validation rules for Organization

	if m.GetUserSearch() == nil {
		return LdapConfigValidationError{
			field:  "UserSearch",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetUserSearch()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return LdapConfigValidationError{
				field:  "UserSearch",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetGroupSearch() == nil {
		return LdapConfigValidationError{
			field:  "GroupSearch",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetGroupSearch()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return LdapConfigValidationError{
				field:  "GroupSearch",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// LdapConfigValidationError is the validation error returned by
// LdapConfig.Validate if the designated constraints aren't met.
type LdapConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e LdapConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e LdapConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e LdapConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e LdapConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e LdapConfigValidationError) ErrorName() string { return "LdapConfigValidationError" }

// Error satisfies the builtin error interface
func (e LdapConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sLdapConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = LdapConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = LdapConfigValidationError{}

// Validate checks the field values on UserSearch with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *UserSearch) Validate() error {
	if m == nil {
		return nil
	}

	if utf8.RuneCountInString(m.GetBaseDN()) < 2 {
		return UserSearchValidationError{
			field:  "BaseDN",
			reason: "value length must be at least 2 runes",
		}
	}

	// no validation rules for Filter

	// no validation rules for Username

	if _, ok := _UserSearch_Scope_InLookup[m.GetScope()]; !ok {
		return UserSearchValidationError{
			field:  "Scope",
			reason: "value must be in list [ sub one]",
		}
	}

	// no validation rules for IdAttr

	// no validation rules for EmailAttr

	// no validation rules for NameAttr

	// no validation rules for EmailSuffix

	return nil
}

// UserSearchValidationError is the validation error returned by
// UserSearch.Validate if the designated constraints aren't met.
type UserSearchValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e UserSearchValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e UserSearchValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e UserSearchValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e UserSearchValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e UserSearchValidationError) ErrorName() string { return "UserSearchValidationError" }

// Error satisfies the builtin error interface
func (e UserSearchValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUserSearch.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = UserSearchValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = UserSearchValidationError{}

var _UserSearch_Scope_InLookup = map[string]struct{}{
	"":    {},
	"sub": {},
	"one": {},
}

// Validate checks the field values on GroupSearch with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *GroupSearch) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for BaseDN

	// no validation rules for Filter

	if _, ok := _GroupSearch_Scope_InLookup[m.GetScope()]; !ok {
		return GroupSearchValidationError{
			field:  "Scope",
			reason: "value must be in list [ sub one]",
		}
	}

	// no validation rules for UserAttr

	// no validation rules for GroupAttr

	// no validation rules for NameAttr

	return nil
}

// GroupSearchValidationError is the validation error returned by
// GroupSearch.Validate if the designated constraints aren't met.
type GroupSearchValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GroupSearchValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GroupSearchValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GroupSearchValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GroupSearchValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GroupSearchValidationError) ErrorName() string { return "GroupSearchValidationError" }

// Error satisfies the builtin error interface
func (e GroupSearchValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGroupSearch.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GroupSearchValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GroupSearchValidationError{}

var _GroupSearch_Scope_InLookup = map[string]struct{}{
	"":    {},
	"sub": {},
	"one": {},
}
