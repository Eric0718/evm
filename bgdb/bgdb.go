package bgdb

import (
	"fmt"
	"kortho/evm/bgdb/store"
	"time"

	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/syndtr/goleveldb/leveldb/errors"
)

const (
	// degradationWarnInterval specifies how often warning should be printed if the
	// leveldb database cannot keep up with requested writes.
	degradationWarnInterval = time.Minute

	// minCache is the minimum amount of memory in megabytes to allocate to leveldb
	// read and write caching, split half and half.
	minCache = 16

	// minHandles is the minimum number of files handles to allocate to the open
	// database files.
	minHandles = 16

	// metricsGatheringInterval specifies the interval to retrieve leveldb database
	// compaction, io and pause stats to report to the user.
	metricsGatheringInterval = 3 * time.Second
)

var (
	errClosed       = errors.New("database closed")
	errNotFound     = errors.New("not found")
	errNotSupported = errors.New("this operation is not supported")
)

// Database is a persistent key-value store. Apart from basic data storage
// functionality it also supports batch writes and iterating over the keyspace in
// binary-alphabetical order.

type Database struct {
	DB store.DB
}

// New returns a wrapped LevelDB object. The namespace is the prefix that the
// metrics reporting should use for surfacing internal stats.
func NewBadgerDatabase(db store.DB) *Database {
	return &Database{db}
}

// Close stops the metrics collection, flushes any pending data to disk and closes
// all io accesses to the underlying key-value store.
func (db *Database) Close() error {
	//return db.Close()
	return nil
}

// Has retrieves if a key is present in the key-value store.
func (db *Database) Has(key []byte) (bool, error) {
	_, err := db.DB.Get(key)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Get retrieves the given key if it's present in the key-value store.
func (db *Database) Get(key []byte) ([]byte, error) {
	return db.DB.Get(key)
}

// Put inserts the given value into the key-value store.
func (db *Database) Put(key []byte, value []byte) error {
	return db.DB.Set(key, value)
}

// Delete removes the key from the key-value store.
func (db *Database) Delete(key []byte) error {
	return db.DB.Del(key)
}

// NewBatch creates a write-only key-value store that buffers changes to its host
// database until a final write is called.
func (db *Database) NewBatch() ethdb.Batch {
	return &batch{
		db: db.DB,
	}
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix, starting at a particular
// initial key (or after, if it does not exist).
func (db *Database) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	return db.DB.NewIterator(prefix, start)
}

// keyvalue is a key-value tuple tagged with a deletion field to allow creating
// memory-database write batches.
type keyvalue struct {
	key    []byte
	value  []byte
	delete bool
}

// batch is a write-only leveldb batch that commits changes to its host database
// when Write is called. A batch cannot be used concurrently.
type batch struct {
	db store.DB

	writes []keyvalue
	size   int
}

// Put inserts the given value into the batch for later committing.
func (b *batch) Put(key, value []byte) error {
	b.writes = append(b.writes, keyvalue{key, value, false})
	{
		//fmt.Printf("****dbset: %v\n", key)
	}
	b.size += len(value)
	return nil //b.db.Set(key, value)
}

// Delete inserts the a key removal into the batch for later committing.
func (b *batch) Delete(key []byte) error {
	b.writes = append(b.writes, keyvalue{key, nil, true})
	{
		fmt.Printf("delete %v\n", key)
	}
	b.size++
	return nil
}

// ValueSize retrieves the amount of data queued up for writing.
func (b *batch) ValueSize() int {
	return b.size
}

// Write flushes any accumulated data to disk.
func (b *batch) Write() error {
	for _, keyvalue := range b.writes {
		if keyvalue.delete {
			b.db.Del(keyvalue.key)
			continue
		}
		{
			//fmt.Printf("****db.set %v\n", keyvalue.key)
		}
		b.db.Set(keyvalue.key, keyvalue.value)
	}
	return nil
}

// Reset resets the batch for reuse.
func (b *batch) Reset() {
	b.writes = b.writes[:0]
	b.size = 0
}

//Replay replays the batch contents.
func (b *batch) Replay(w ethdb.KeyValueWriter) error {
	for _, keyvalue := range b.writes {
		if keyvalue.delete {
			if err := w.Delete(keyvalue.key); err != nil {
				return err
			}
			continue
		}
		if err := w.Put(keyvalue.key, keyvalue.value); err != nil {
			return err
		}
	}
	return nil
}

// replayer is a small wrapper to implement the correct replay methods.
type replayer struct {
	writer  ethdb.KeyValueWriter
	failure error
}

// Put inserts the given value into the key-value data store.
func (r *replayer) Put(key, value []byte) {
	// If the replay already failed, stop executing ops
	if r.failure != nil {
		return
	}
	r.failure = r.writer.Put(key, value)
}

// Delete removes the key from the key-value data store.
func (r *replayer) Delete(key []byte) {
	// If the replay already failed, stop executing ops
	if r.failure != nil {
		return
	}
	r.failure = r.writer.Delete(key)
}

func (db *Database) Stat(property string) (string, error) {
	return "", errors.New("unknown property")
}

func (db *Database) Compact(start []byte, limit []byte) error {
	fmt.Printf("Compact: start [%v]>>>>>>>>>limit[%v]>>>>>>>>\n", start, limit)
	return nil
}

func (db *Database) HasAncient(kind string, number uint64) (bool, error) {
	return false, errNotSupported
}

func (db *Database) Ancient(kind string, number uint64) ([]byte, error) {
	return nil, errNotSupported
}

func (db *Database) Ancients() (uint64, error) {
	return 0, errNotSupported
}

func (db *Database) AncientSize(kind string) (uint64, error) {
	return 0, errNotSupported
}

func (db *Database) AppendAncient(number uint64, hash, header, body, receipt, td []byte) error {
	return errNotSupported
}

func (db *Database) TruncateAncients(n uint64) error {
	return errNotSupported
}

func (db *Database) Sync() error {
	return db.DB.Sync()
}
