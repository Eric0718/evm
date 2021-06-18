package bg

import (
	"fmt"
	"kortho/evm/bgdb/store"

	"github.com/dgraph-io/badger"
)

func New(name string) store.DB {
	opts := badger.DefaultOptions(name)
	if db, err := badger.Open(opts); err != nil {
		fmt.Println("Open database error:", err)
		return nil
	} else {
		return &bgStore{db}
	}
}

func (db *bgStore) Sync() error {
	return db.db.Sync()
}

func (db *bgStore) Close() error {
	return db.db.Close()
}

func (db *bgStore) Del(k []byte) error {
	tx := db.db.NewTransaction(true)
	defer tx.Discard()
	if err := del(tx, k); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *bgStore) Set(k, v []byte) error {
	tx := db.db.NewTransaction(true)
	defer tx.Discard()
	if err := set(tx, k, v); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *bgStore) Get(k []byte) ([]byte, error) {
	tx := db.db.NewTransaction(false)
	defer tx.Discard()
	return get(tx, k)
}

func (db *bgStore) NewTransaction() store.Transaction {
	tx := db.db.NewTransaction(true)
	return &bgTransaction{tx}
}

func (tx *bgTransaction) Cancel() error {
	tx.tx.Discard()
	return nil
}

func (tx *bgTransaction) Commit() error {
	return tx.tx.Commit()
}

func (tx *bgTransaction) Del(k []byte) error {
	return del(tx.tx, k)
}

func (tx *bgTransaction) Set(k, v []byte) error {
	return set(tx.tx, k, v)
}

func (tx *bgTransaction) Get(k []byte) ([]byte, error) {
	return get(tx.tx, k)
}

func del(tx *badger.Txn, k []byte) error {
	return tx.Delete(k)
}

func set(tx *badger.Txn, k, v []byte) error {
	return tx.Set(k, v)
}

func get(tx *badger.Txn, k []byte) ([]byte, error) {
	it, err := tx.Get(k)
	if err == badger.ErrKeyNotFound {
		err = store.NotExist
	}
	if err != nil {
		return nil, err
	}
	return it.ValueCopy(nil)
}
