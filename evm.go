package evm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"kortho/config"
	"kortho/evm/bgdb"
	"kortho/evm/bgdb/store/bg"
	"log"
	"math"
	"math/big"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

// Evm struct
type Evm struct {
	cfg  *runtime.Config
	edb  *badger.DB
	cdb  *bgdb.Database
	root common.Hash
	sdb  state.Database
}

var (
	COMMONHASH = []byte("CommonHash")
	LASTHASH   = []byte("LastHash")
	COMMONADDR = []byte("CommonAddress")
	HEIGHTHASH = []byte("HeightHash")
	LOGS       = []byte("Logs")
)

const (
	notExist = "NotExist"
)

func NewEvm() (*Evm, error) {
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	opts := badger.DefaultOptions("./DB/evm.db")
	edb, err := badger.Open(opts)
	if err != nil {
		log.Printf("badger.Open=====%v\n", err)
		return nil, err
	}
	cdb := bgdb.NewBadgerDatabase(bg.New("./DB/evmcontractdb.db"))
	sdb := state.NewDatabase(cdb)

	e := &Evm{cfg: new(runtime.Config), edb: edb, cdb: cdb, sdb: sdb, root: common.Hash{}}
	setDefaults(e.cfg)

	e.root = common.Hash{}
	v, err := e.mget(LASTHASH, LASTHASH)
	if err == nil {
		e.root = common.BytesToHash(v)
	}
	log.Println("get state root:", e.root)

	st, err := state.New(e.root, e.sdb, nil)
	if err != nil {
		fmt.Printf("state.New=====%v\n", err)
		return nil, err
	}
	e.cfg.State = st

	//load logs
	logKeys, _ := e.GetKeys(LOGS)
	if err != nil {
		log.Printf("GetKeys error %v!!!\n", err)
	}
	for _, hash := range logKeys {
		lg, err := e.mget(LOGS, hash)
		if err != nil {
			log.Printf("mget log error %v!!!\n", err)
		}
		var logs []*types.Log
		err = json.Unmarshal(lg, &logs)
		if err != nil {
			log.Printf("Unmarshal  log error %v!!!\n", err)
		}
		for _, l := range logs {
			e.cfg.State.Prepare(common.BytesToHash(hash), l.BlockHash, int(l.Index))
			e.cfg.State.AddLog(l)
		}

	}
	return e, nil
}

func (e *Evm) RollBackRoot(pos, max uint64) error {
	var preHash []byte
	for hi := pos; hi <= max; hi++ {
		hash, err := e.mget(COMMONHASH, E64func(pos+1))
		if err != nil {
			continue
		}
		preHash = append(preHash, hash...)
		break
	}

	currHash := preHash
	hi := pos
	if len(preHash) > 0 {
		log.Printf("get previous root hash:%v\n", common.BytesToHash(preHash))
		for ; bytes.Equal(currHash, preHash); hi-- {
			hash, err := e.mget(COMMONHASH, E64func(hi))
			if err != nil {
				continue
			}
			currHash = hash
		}
		//roll back last hash to currHash
		err := e.mset(LASTHASH, LASTHASH, currHash)
		if err != nil {
			return err
		}
		log.Printf("roll back root hash to height: %v,root:%v\n", hi, common.BytesToHash(currHash))
	}

	return nil
}

func (e *Evm) RawDump() state.Dump {
	if e.cfg.State != nil {
		return e.cfg.State.RawDump(false, false, false)
	}

	log.Println("GetDump failed!")
	return state.Dump{}
}

func (e *Evm) Create(code []byte, origin common.Address) ([]byte, common.Address, uint64, error) {
	if len(origin) > 0 {
		e.cfg.Origin = origin
	}
	return runtime.Create(code, e.cfg)
}

func (e *Evm) Call(contAddr common.Address, origin common.Address, inputCode []byte) ([]byte, uint64, error) {
	log.Printf("contract address:[%v],inputCode{%v},origin[%v]", contAddr, common.Bytes2Hex(inputCode), origin)
	getcode := e.cfg.State.GetCode(contAddr)
	if len(getcode) <= 0 {
		return nil, 0, fmt.Errorf("Call error:GetCode failed by contractaddress[%v]", contAddr)
	}

	e.cfg.State.SetCode(contAddr, e.cfg.State.GetCode(contAddr))
	e.cfg.Origin = origin

	return runtime.Call(contAddr, inputCode, e.cfg)
}

func (e *Evm) GetCode(contAddr common.Address) []byte {
	return e.cfg.State.GetCode(contAddr)
}

func (e *Evm) StateCommit(deleteEmptyObjects bool, height uint64, name string, contractAddr common.Address, txHash common.Hash) (common.Hash, error) {
	log.Printf("Into statecommit>>>>>>>>>>>>>>\n")
	commonHash, err := e.cfg.State.Commit(deleteEmptyObjects)
	if err != nil {
		return common.Hash{}, err
	}
	log.Println("common hash:", commonHash)

	triDB := e.cfg.State.Database().TrieDB()
	err = triDB.Commit(commonHash, true, nil)
	if err != nil {
		return common.Hash{}, err
	}
	//common hash -> common hash
	err = e.mset(COMMONHASH, commonHash.Bytes(), commonHash.Bytes())
	if err != nil {
		return common.Hash{}, err
	}
	//balock height -> common hash
	if height > 0 {
		err = e.mset(HEIGHTHASH, E64func(height), commonHash.Bytes())
		if err != nil {
			return common.Hash{}, err
		}
	}

	//store last common hash
	err = e.mset(LASTHASH, LASTHASH, commonHash.Bytes())
	if err != nil {
		return common.Hash{}, err
	}

	//store logs
	logs := e.cfg.State.GetLogs(txHash)
	if len(logs) > 0 {
		btLogs, _ := json.Marshal(logs)

		err = e.mset(LOGS, txHash.Bytes(), btLogs)
		if err != nil {
			log.Println("store logs error!!!", err)
		}
	}

	log.Println("End statecommit>>>>>>>>>>>>>>")
	return commonHash, nil
}

func (e *Evm) Prepare(txhash, blhash common.Hash, txindex int) {
	log.Println("Prepare>>>>>>>>>>>>>>txhash, blhash, txindex:", txhash, blhash, txindex)
	e.cfg.State.Prepare(txhash, blhash, txindex)
}

func (e *Evm) AddLog(lg *types.Log) {
	log.Println("Evm AddLog>>>>>>>>>>>>>>", lg.Address, lg.Topics)
	e.cfg.State.AddLog(lg)
}

func (e *Evm) GetLogs(cmhash common.Hash) []*types.Log {
	return e.cfg.State.GetLogs(cmhash)
}
func (e *Evm) Logs() []*types.Log {
	return e.cfg.State.Logs()
}

func (e *Evm) SetBlockInfo(num uint64, miner string, tm uint64) {
	//log.Println("SetBlockInfo>>>>>>>>>>>>>> height,miner:", num, miner)
	if num >= 0 {
		e.cfg.BlockNumber = new(big.Int).SetUint64(num)
	}
	if len(miner) > 0 {
		e.cfg.Coinbase = common.HexToAddress(miner)
	}
	if tm != 0 {
		e.cfg.Time = new(big.Int).SetUint64(tm)
	}

}

func (e *Evm) SetValue(val, price *big.Int) {
	log.Println("SetValue>>>>>>>>>>>>>> Value,GasPrice:", val, price)
	e.cfg.Value = val
	e.cfg.GasPrice = price
}

func (e *Evm) AddBalance(addr common.Address, amount *big.Int) {
	fmt.Println("Evm AddBalance>>>>>>>", addr, amount)
	e.cfg.State.AddBalance(addr, amount)
}

func (e *Evm) SubBalance(addr common.Address, amount *big.Int) {
	e.cfg.State.SubBalance(addr, amount)
}

func (e *Evm) SetBalance(addr common.Address, amount *big.Int) {
	e.cfg.State.SetBalance(addr, amount)
}

func (e *Evm) GetBalance(addr common.Address) *big.Int {
	return e.cfg.State.GetBalance(addr)
}

func (e *Evm) GetNonce(addr common.Address) uint64 {
	return e.cfg.State.GetNonce(addr)
}

func (e *Evm) GetStorageAt(addr common.Address, hash common.Hash) common.Hash {
	proof := e.cfg.State.GetState(addr, hash)

	fmt.Printf("proof:%v\n", proof)
	return proof
}

func (e *Evm) GetSnapshot() int {
	return e.cfg.State.Snapshot()
}

func (e *Evm) RevertToSnapshot(sp int) {
	e.cfg.State.RevertToSnapshot(sp)

}

func (e *Evm) GetCommonAddress(name string) (common.Address, error) {
	v, err := e.mget(COMMONADDR, []byte(name))
	if err != nil {
		return common.Address{}, err
	}
	return common.BytesToAddress(v), nil
}

func (e *Evm) CloseDB() {
	if e.edb != nil {
		e.edb.Close()
	}

	if e.cdb != nil {
		e.cdb.Close()
	}
}

// sets defaults on the config
func setDefaults(cfg *runtime.Config) {
	if cfg.ChainConfig == nil {
		cfg.ChainConfig = &params.ChainConfig{
			ChainID:             big.NewInt(config.GlobalCfg.BFTConfig.ChainId),
			HomesteadBlock:      new(big.Int),
			DAOForkBlock:        new(big.Int),
			DAOForkSupport:      false,
			EIP150Block:         new(big.Int),
			EIP150Hash:          common.Hash{},
			EIP155Block:         new(big.Int),
			EIP158Block:         new(big.Int),
			ByzantiumBlock:      new(big.Int),
			ConstantinopleBlock: new(big.Int),
			PetersburgBlock:     new(big.Int),
			IstanbulBlock:       new(big.Int),
			MuirGlacierBlock:    new(big.Int),
			YoloV3Block:         nil,
		}
	}

	if cfg.Difficulty == nil {
		cfg.Difficulty = new(big.Int)
	}
	if cfg.Time == nil {
		cfg.Time = big.NewInt(time.Now().Unix())
	}
	if cfg.GasLimit == 0 {
		cfg.GasLimit = math.MaxUint64
	}
	if cfg.GasPrice == nil {
		cfg.GasPrice = new(big.Int)
	}
	if cfg.Value == nil {
		cfg.Value = new(big.Int)
	}
	if cfg.BlockNumber == nil {
		cfg.BlockNumber = new(big.Int)
	}
	if cfg.GetHashFn == nil {
		cfg.GetHashFn = func(n uint64) common.Hash {
			return common.BytesToHash(crypto.Keccak256([]byte(new(big.Int).SetUint64(n).String())))
		}
	}
}

func set(tx *badger.Txn, k, v []byte) error {
	return tx.Set(k, v)
}

func get(tx *badger.Txn, k []byte) ([]byte, error) {
	it, err := tx.Get(k)
	if err == badger.ErrKeyNotFound {
		err = fmt.Errorf(notExist)
	}
	if err != nil {
		return nil, err
	}
	return it.ValueCopy(nil)
}

func del(tx *badger.Txn, k []byte) error {
	return tx.Delete(k)
}

func (e *Evm) mset(m, k, v []byte) error {
	tx := e.edb.NewTransaction(true)
	defer tx.Discard()
	if err := set(tx, eMapKey(m, k), v); err != nil {
		return err
	}
	return tx.Commit()
}

func (e *Evm) mget(m, k []byte) ([]byte, error) {
	tx := e.edb.NewTransaction(true)
	defer tx.Discard()

	return get(tx, eMapKey(m, k))
}

func (e *Evm) mdel(m, k []byte) error {
	tx := e.edb.NewTransaction(true)
	defer tx.Discard()
	return del(tx, eMapKey(m, k))
}

func (e *Evm) GetKeys(m []byte) ([][]byte, error) {
	tx := e.edb.NewTransaction(false)
	defer tx.Discard()
	return mkeys(tx, m)
}

func mkeys(tx *badger.Txn, m []byte) ([][]byte, error) {
	var ks [][]byte

	k := eMapKey(m, []byte{})
	opt := badger.DefaultIteratorOptions
	opt.Prefix = k
	opt.PrefetchValues = false
	itr := tx.NewIterator(opt)
	defer itr.Close()
	for itr.Seek(k); itr.ValidForPrefix(k); itr.Next() {
		ks = append(ks, dMapKey(itr.Item().KeyCopy(nil)))
	}
	return ks, nil
}

// 'm' + mlen + m + '+' + k
func eMapKey(m, k []byte) []byte {
	buf := []byte{}
	buf = append([]byte{'m'}, E32func(uint32(len(m)))...)
	buf = append(buf, m...)
	buf = append(buf, byte('+'))
	buf = append(buf, k...)
	return buf
}

func E32func(a uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, a)
	return buf
}

func dMapKey(buf []byte) []byte {
	buf = buf[1:]
	n, _ := D32func(buf[:4])
	return buf[5+n:]
}
func D32func(a []byte) (uint32, error) {
	if len(a) != 4 {
		return 0, errors.New("D32func: Illegal slice length")
	}
	return binary.LittleEndian.Uint32(a), nil
}

func E64func(a uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, a)
	return buf
}

func CreateAccount() (string, error) {
	fmt.Println("Into CreateAccount>>>>")
	entropy, _ := bip39.NewEntropy(128)       //熵增
	mnemonic, _ := bip39.NewMnemonic(entropy) //助记词
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", err
	}

	//pri, _ := wallet.PrivateKeyHex(account)
	fmt.Println("End CreateAccount>>>>", account)
	return account.Address.Hex(), nil

}

func (e *Evm) GetContractAddress(name string) (common.Address, error) {
	addr, err := e.mget(COMMONADDR, []byte(name))
	if err != nil {
		return common.Address{}, err
	}
	return common.BytesToAddress(addr), nil
}
