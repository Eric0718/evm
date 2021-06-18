package bg

import (
	"kortho/evm/bgdb/store"

	"github.com/dgraph-io/badger"
)

func (db *bgStore) NewIterator(prefix []byte, start []byte) store.Iterator {
	opt := badger.DefaultIteratorOptions
	opt.Prefix = prefix
	opt.PrefetchValues = false
	tx := db.db.NewTransaction(false)
	itr := tx.NewIterator(opt)
	itr.Seek(start)
	return &bgIterator{
		tx:  tx,
		itr: itr,
	}
}

func (itr *bgIterator) Next() bool {
	if !itr.itr.Valid() {
		return false
	}
	itr.itr.Next()
	return itr.itr.Valid()

}

func (itr *bgIterator) Error() error {
	return itr.err
}

func (itr *bgIterator) Key() []byte {
	return itr.itr.Item().KeyCopy(nil)
}

func (itr *bgIterator) Value() []byte {
	v, err := itr.itr.Item().ValueCopy(nil)
	if err != nil {
		itr.err = err
		return nil
	}
	return v
}

func (itr *bgIterator) Release() {
	itr.itr.Close()
	itr.tx.Discard()
}
