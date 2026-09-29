package token

import "errors"

var (
	ErrMalformed      = errors.New("malformed token")
	ErrBadSignature   = errors.New("bad signature")
	ErrExpired        = errors.New("expired token")
	ErrWrongType      = errors.New("wrong token type")
	ErrWrongNode      = errors.New("wrong node")
	ErrDisallowedSize = errors.New("disallowed download size")
	ErrDisallowedTool = errors.New("disallowed tool")
	ErrIPBinding      = errors.New("ip binding failed")
	ErrReplay         = errors.New("nonce replay")
	ErrInvalidNonce   = errors.New("invalid nonce")
	ErrUnknownKID     = errors.New("unknown kid")
)
