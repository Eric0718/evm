package store

import "errors"

var (
	NotExist  = errors.New("NotExist")
	OutOfSize = errors.New("Out of Size")
)

type DB interface {
	Sync() error

	Close() error
	// kv
	Del([]byte) error
	Set([]byte, []byte) error
	Get([]byte) ([]byte, error)

	NewTransaction() Transaction
	NewIterator([]byte, []byte) Iterator
}

type Transaction interface {
	Commit() error
	Cancel() error

	// kv
	Del([]byte) error
	Set([]byte, []byte) error
	Get([]byte) ([]byte, error)
}

type Iterator interface {
	Next() bool

	Error() error

	Key() []byte

	Value() []byte

	Release()
}
