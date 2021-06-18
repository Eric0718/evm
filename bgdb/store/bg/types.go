package bg

import "github.com/dgraph-io/badger"

type bgStore struct {
	db *badger.DB
}

type bgTransaction struct {
	tx *badger.Txn
}

type bgIterator struct {
	err error
	tx  *badger.Txn
	itr *badger.Iterator
}
