package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewalletmlp/walletdb"
)

// Naming
//
// The following variables are commonly used in this file and given
// reserved names:
//
//   ns: The namespace bucket for this package
//   b:  The primary bucket being operated on
//   k:  A single bucket key
//   v:  A single bucket value
//   c:  A bucket cursor
//   ck: The current cursor key
//   cv: The current cursor value
//
// Functions use the naming scheme `Op[Raw]Type[Field]`, which performs the
// operation `Op` on the type `Type`, optionally dealing with raw keys and
// values if `Raw` is used.  Fetch and extract operations may only need to read
// some portion of a key or value, in which case `Field` describes the component
// being returned.  The following operations are used:
//
//   key:     return a db key for some data
//   value:   return a db value for some data
//   put:     insert or replace a value into a bucket
//   fetch:   read and return a value
//   read:    read a value into an out parameter
//   exists:  return the raw (nil if not found) value for some data
//   delete:  remove a k/v pair
//   extract: perform an unchecked slice to extract a key or value
//
// Other operations which are specific to the types being operated on
// should be explained in a comment.

// Big endian is the preferred byte order, due to cursor scans over integer
// keys iterating in order.
var byteOrder = binary.BigEndian

// This package makes assumptions that the width of a chainhash.Hash is always
// 32 bytes.  If this is ever changed (unlikely for bitcoin, possible for alts),
// offsets have to be rewritten.  Use a compile-time assertion that this
// assumption holds true.
var _ [32]byte = chainhash.Hash{}

const NUMBERBLOCK = 24 //TODO(abe):this value need to think about

// Bucket names
var (
	bucketRequestRecord = []byte("request")

	bucketTxLabels      = []byte("l")  // not support now, but it may be supported
	bucketLockedOutputs = []byte("lo") // not support now, but it may be supported

	//TODO(abe):bucket design
	bucketBlocks       = []byte("blocksabe") // store blocks
	bucketBlockOutputs = []byte("blockoutputs")
	bucketBlockInputs  = []byte("blockinputs")

	bucketImmaturedCoinbaseOutput = []byte("immaturedcoinbaseoutput")
	bucketImmaturedOutput         = []byte("immaturedeoutput")
	bucketMaturedOutput           = []byte("maturedoutput")
	bucketSpentButUnmined         = []byte("spentbutumined")
	bucketSpentConfirmed          = []byte("spentconfirmed")

	//bucketAUTEntry = []byte("autentry") // autname -> autentry [outpoint -> aut coin]

	bucketAUTPoint              = []byte("autpoint") // outpoint -> aut coin
	bucketBlockDisabledAUTPoint = []byte("blockdisabledautpoints")

	bucketCTAUTPoint              = []byte("ctautpoint") // outpoint -> aut coin
	bucketBlockDisabledCTAUTPoint = []byte("blockdisabledctautpoints")

	bucketUTXORing    = []byte("utxoring")
	bucketRingDetails = []byte("utxoringdetails") //TODO(abe):we should add a block height in database, meaning that the txo in ring had consumed completely .

	bucketUnconfirmedTx = []byte("unconfirmedtx") // unconfirmed transaction
	bucketInvalidTx     = []byte("invalidtx")     // invalid transaction
	bucketConfirmedTx   = []byte("confirmedtx")   // confirmed transaction

	// map transaction output to transaction hash set
	bucketRelevantTxs = []byte("relevanttxs") // relevant transaction set: (txhash,index) -> [relevant transaction hashes]
)

// Root (namespace) bucket keys
var (
	rootCreateDate              = []byte("date")
	rootVersion                 = []byte("vers")
	rootMinedBalance            = []byte("bal")            // total balance
	rootSpendableBalance        = []byte("spendablebal")   // spendable balance
	rootImmatureCoinbaseBalance = []byte("immaturecbbal")  // immature coinbase balance
	rootImmatureTransferBalance = []byte("immaturetrbal")  // immature transfer balance
	rootUnconfirmedBalance      = []byte("unconfirmedbal") // spendable balance
	rootFreezedBalance          = []byte("freezedbal")     // freeze balance

	rootAUTBalance                = []byte("autbal")              // total balance for aut
	rootAUTImmatureRootCoinNum    = []byte("autimmaturecbnum")    // immature transfer balance for aut
	rootAUTSpendableRootCoinNum   = []byte("autspendablecbnum")   // spendable balance for aut
	rootAUTUnconfirmedRootCoinNum = []byte("autunconfirmedcbnum") // spendable balance for aut

	rootAUTRootCoinNum             = []byte("autcbnum")          // total balance for aut
	rootAUTImmatureTransferBalance = []byte("autimmaturetrbal")  // immature transfer balance for aut
	rootAUTSpendableBalance        = []byte("autspendablebal")   // spendable balance for aut
	rootAUTUnconfirmedBalance      = []byte("autunconfirmedbal") // spendable balance for aut

	rootAUTFreezedBalance = []byte("autfreezedbal") // freeze balance for aut, this type balance for aut is not supported now

	rootCTAUTBalance                = []byte("ctautbal")              // total balance for aut
	rootCTAUTImmatureRootCoinNum    = []byte("ctautimmaturecbnum")    // immature transfer balance for aut
	rootCTAUTSpendableRootCoinNum   = []byte("ctautspendablecbnum")   // spendable balance for aut
	rootCTAUTUnconfirmedRootCoinNum = []byte("ctautunconfirmedcbnum") // spendable balance for aut

	rootCTAUTRootCoinNum             = []byte("ctautcbnum")          // total balance for aut
	rootCTAUTImmatureTransferBalance = []byte("ctautimmaturetrbal")  // immature transfer balance for aut
	rootCTAUTSpendableBalance        = []byte("ctautspendablebal")   // spendable balance for aut
	rootCTAUTUnconfirmedBalance      = []byte("ctautunconfirmedbal") // spendable balance for aut

	rootCTAUTFreezedBalance = []byte("ctautfreezedbal") // freeze balance for aut, this type balance for aut is not supported now
)

// The root bucket's mined balance k/v pair records the total balance for all
// unspent credits from mined transactions.  This includes immature outputs, and
// outputs spent by mempool transactions, which must be considered when
// returning the actual balance for a given number of block confirmations.  The
// value is the amount serialized as a uint64.
func fetchMinedBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootMinedBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}

func putMinedBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootMinedBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchSpendableBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootSpendableBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}

func putSpendableBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootSpendableBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchFreezeBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootFreezedBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}

func putFreezeBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootFreezedBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchImmatureCoinbaseBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootImmatureCoinbaseBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}
func putImmatureCoinbaseBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootImmatureCoinbaseBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchImmatureTransferBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootImmatureTransferBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}
func putImmatureTransferBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootImmatureTransferBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchUnconfirmedBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootUnconfirmedBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}
func putUnconfirmedBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootUnconfirmedBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// Several data structures are given canonical serialization formats as either
// keys or values.  These common formats allow keys and values to be reused
// across different buckets.
//
// The canonical outpoint serialization format is:
//
//   [0:32]  Trasaction hash (32 bytes)
//   [32:36] Output index (4 bytes)
//
// The canonical transaction hash serialization is simply the hash.

// TODO(abe):the type of index can not be to serialize have no one of PutUint8?

// The canonical outpoint serialization format is:
//
//	[0:32]  Transaction hash (32 bytes)
//	[32:33] Output index (1 byte)
//
// The canonical transaction hash serialization is simply the hash.
func canonicalOutPointAbe(txHash chainhash.Hash, index uint8) []byte {
	var k [chainhash.HashSize + 1]byte
	copy(k[:chainhash.HashSize], txHash[:])
	k[chainhash.HashSize] = index
	return k[:]
}
func readCanonicalOutPointAbe(k []byte, op *wire.OutPointAbe) error {
	if len(k) < chainhash.HashSize+1 {
		str := "short canonical outpoint"
		return storeError(ErrData, str, nil)
	}
	copy(op.TxHash[:], k[:chainhash.HashSize])
	op.Index = k[chainhash.HashSize]
	return nil
}
func canonicalBlock(blockHeight int32, blockHash chainhash.Hash) []byte {
	var k [4 + chainhash.HashSize]byte
	byteOrder.PutUint32(k[0:4], uint32(blockHeight))
	copy(k[4:], blockHash[:])
	return k[:]
}

// Details regarding blocks are saved as k/v pairs in the blocks bucket.
// blockRecords are keyed by their height.  The value is serialized as such:
//
//   [0:32]  Hash (32 bytes)
//   [32:40] Unix time (8 bytes)
//   [40:44] Number of transaction hashes (4 bytes)
//   [44:]   For each transaction hash:
//             Hash (32 bytes)

// Details regarding raw block are saved as k/v pairs in the rawblock bucket.
// rawblock are keyed by their height and hash.
// The key is serialized as such:
//
//	[0:4] Height(4 bytes)
//	[4:36]  Hash (32 bytes)
//
// The value is serialized as such:
//
//	[0:80] Header(80 bytes)
//	[80:84]Number of transaction (32 bytes)
//	[84:] transactions?
func putBlockRecord(ns walletdb.ReadWriteBucket, block *BlockRecord) error {
	var err error
	if block == nil {
		return errors.New("block with nil pointer")
	}
	k := canonicalBlock(block.Height, block.Hash)
	v := block.SerializedBlock
	if len(v) == 0 {
		var w bytes.Buffer
		err = block.MsgBlock.SerializeNoWitness(&w)
		if err != nil {
			return err
		}
		v = w.Bytes()
	}
	err = ns.NestedReadWriteBucket(bucketBlocks).Put(k, v)
	if err != nil {
		str := "failed to store block"
		return storeError(ErrDatabase, str, err)
	}

	res := new(wire.MsgBlockAbe)
	err = res.Deserialize(bytes.NewReader(v))
	if err != nil {
		panic("MsgBlockAbe has unmatched serialization/deserialization ")
	}
	var tmp bytes.Buffer

	err = res.Serialize(&tmp)
	if err != nil {
		panic("MsgBlockAbe has unmatched serialization/deserialization ")
	}
	if !reflect.DeepEqual(tmp.Bytes(), v) {
		panic("MsgBlockAbe has unmatched serialization/deserialization ")
	}

	return nil
}
func fetchBlockRecord(ns walletdb.ReadBucket, height int32, hash chainhash.Hash) (*BlockRecord, error) {
	k := canonicalBlock(height, hash)
	v := ns.NestedReadBucket(bucketBlocks).Get(k)
	if len(v) == 0 {
		return nil, nil
	}
	msgBlock := new(wire.MsgBlockAbe)
	err := msgBlock.Deserialize(bytes.NewReader(v))
	if err != nil {
		return nil, err
	}
	return NewBlockRecordFromMsgBlock(msgBlock)
}

func deleteRawBlock(ns walletdb.ReadWriteBucket, k []byte) error {
	return ns.NestedReadWriteBucket(bucketBlocks).Delete(k)
}
func deleteRawBlockWithBlockHeight(ns walletdb.ReadWriteBucket, height int32) error {
	// iterator the block bucket
	err := ns.NestedReadBucket(bucketBlocks).ForEach(func(k, v []byte) error {
		if height == int32(byteOrder.Uint32(k[0:4])) {
			return deleteRawBlock(ns, k)
		}
		return nil
	})
	return err
}

// appendRawBlockRecord returns a new block record value with a transaction
// hash appended to the end and an incremented number of transactions.

// TODO(abe):this struct test some problem, need to fix
type blockIterator struct {
	c      walletdb.ReadWriteCursor
	prefix []byte // height
	ck     []byte // height || hash
	cv     []byte
	elem   *BlockRecord
	err    error
}

func makeBlockIterator(ns walletdb.ReadWriteBucket, height int32) blockIterator {
	prefix := make([]byte, 4)
	byteOrder.PutUint32(prefix, uint32(height))
	c := ns.NestedReadWriteBucket(bucketBlocks).ReadWriteCursor()
	return blockIterator{c: c, prefix: prefix}
}

func makeReadBlockIterator(ns walletdb.ReadBucket, height int32) blockIterator {
	prefix := make([]byte, 4)
	byteOrder.PutUint32(prefix, uint32(height))
	c := ns.NestedReadBucket(bucketBlocks).ReadCursor()
	return blockIterator{c: readCursor{c}, prefix: prefix}
}

// Works just like makeBlockIterator but will initially position the cursor at
// the last k/v pair.  Use this with blockIterator.prev.
func makeReverseBlockIterator(ns walletdb.ReadWriteBucket, height int32) blockIterator {
	prefix := make([]byte, 4)
	byteOrder.PutUint32(prefix, uint32(height))
	c := ns.NestedReadWriteBucket(bucketBlocks).ReadWriteCursor()
	return blockIterator{c: c, prefix: prefix}
}

func makeReadReverseBlockIterator(ns walletdb.ReadBucket, height int32) blockIterator {
	prefix := make([]byte, 4)
	byteOrder.PutUint32(prefix, uint32(height))
	c := ns.NestedReadBucket(bucketBlocks).ReadCursor()
	return blockIterator{c: readCursor{c}, prefix: prefix}
}

func (it *blockIterator) prev() bool {
	if it.c == nil {
		return false
	}

	if it.ck == nil {
		it.ck, it.cv = it.c.Seek(it.prefix)
	} else {
		it.ck, it.cv = it.c.Next()
	}
	if it.ck == nil {
		it.c = nil
		return false
	}

	err := it.readElem()
	if err != nil {
		it.c = nil
		it.err = err
		return false
	}

	return true
}
func (it *blockIterator) next() bool {
	if it.c == nil {
		return false
	}

	if it.ck == nil {
		it.ck, it.cv = it.c.Seek(it.prefix)
	} else {
		it.ck, it.cv = it.c.Next()
	}
	if !bytes.HasPrefix(it.ck, it.prefix) {
		it.c = nil
		return false
	}

	err := it.readElem()
	if err != nil {
		it.err = err
		return false
	}
	return true
}

func (it *blockIterator) readElem() error {
	if len(it.ck) < 36 {
		str := fmt.Sprintf("%s: short key (expected %d bytes, read %d)",
			bucketBlocks, 36, len(it.ck))
		return storeError(ErrData, str, nil)
	}
	e, err := NewBlockRecord(it.cv)
	if err != nil {
		return err
	}
	it.elem = e
	return nil
}

// unavailable until https://github.com/boltdb/bolt/issues/620 is fixed.
// func (it *blockIterator) delete() error {
// 	err := it.c.Delete()
// 	if err != nil {
// 		str := "failed to delete block record"
// 		storeError(ErrDatabase, str, err)
// 	}
// 	return nil
// }

// Transaction records are keyed as such:
//
//	[0:32]  Transaction hash (32 bytes)
//	[32:36] Block height (4 bytes)
//	[36:68] Block hash (32 bytes)
//
// The leading transaction hash allows to prefix filter for all records with
// a matching hash.  The block height and hash records a particular incidence
// of the transaction in the blockchain.
//
// The record value is serialized as such:
//
//	[0:8]   Received time (8 bytes)
//	[8:]    Serialized transaction (varies)

func valueTxRecord(rec *TxRecord) ([]byte, error) {
	var v []byte
	if rec.SerializedTx == nil {
		txSize := rec.MsgTx.SerializeSize()
		v = make([]byte, 8, 8+txSize)
		err := rec.MsgTx.Serialize(bytes.NewBuffer(v[8:]))
		if err != nil {
			str := fmt.Sprintf("unable to serialize transaction %v", rec.Hash)
			return nil, storeError(ErrInput, str, err)
		}
		v = v[:cap(v)]
	} else {
		v = make([]byte, 8+len(rec.SerializedTx))
		copy(v[8:], rec.SerializedTx)
	}
	byteOrder.PutUint64(v, uint64(rec.Received.Unix()))
	return v, nil
}

func readRawTxRecord(txHash *chainhash.Hash, v []byte, rec *TxRecord, bucketName []byte) error {
	if len(v) < 8 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketName, 8, len(v))
		return storeError(ErrData, str, nil)
	}
	rec.Hash = *txHash
	rec.Received = time.Unix(int64(byteOrder.Uint64(v)), 0)
	err := rec.MsgTx.Deserialize(bytes.NewReader(v[8:]))
	if err != nil {
		str := fmt.Sprintf("%s: failed to deserialize transaction %v",
			bucketUnconfirmedTx, txHash)
		return storeError(ErrData, str, err)
	}
	return nil
}

// TODO: This reads more than necessary.  Pass the pkscript location instead to
// avoid the wire.MsgTx deserialization.

// latestTxRecord searches for the newest recorded mined transaction record with
// a matching hash.  In case of a hash collision, the record from the newest
// block is returned.  Returns (nil, nil) if no matching transactions are found.

// All transaction credits (outputs) are keyed as such:
//
//   [0:32]  Transaction hash (32 bytes)
//   [32:36] Block height (4 bytes)
//   [36:68] Block hash (32 bytes)
//   [68:72] Output index (4 bytes)
//
// The first 68 bytes match the key for the transaction record and may be used
// as a prefix filter to iterate through all credits in order.
//
// The credit value is serialized as such:
//
//   [0:8]   Amount (8 bytes)
//   [8]     Flags (1 byte)
//             0x01: Spent
//             0x02: Change
//   [9:81]  OPTIONAL Debit bucket key (72 bytes)
//             [9:41]  Spender transaction hash (32 bytes)
//             [41:45] Spender block height (4 bytes)
//             [45:77] Spender block hash (32 bytes)
//             [77:81] Spender transaction input index (4 bytes)
//
// The optional debits key is only included if the credit is spent by another
// mined debit.

// valueUnspentCredit creates a new credit value for an unspent credit.  All
// credits are created unspent, and are only marked spent later, so there is no
// value function to create either spent or unspent credits.

// putUnspentCredit puts a credit record for an unspent credit.  It may only be
// used when the credit is already know to be unspent, or spent by an
// unconfirmed transaction.

// fetchRawCreditAmount returns the amount of the credit.

// fetchRawCreditAmountSpent returns the amount of the credit and whether the
// credit is spent.

// fetchRawCreditAmountChange returns the amount of the credit and whether the
// credit is marked as change.

// fetchRawCreditUnspentValue returns the unspent value for a raw credit key.
// This may be used to mark a credit as unspent.

// spendRawCredit marks the credit with a given key as mined at some particular
// block as spent by the input at some transaction incidence.  The debited
// amount is returned.

// unspendRawCredit rewrites the credit for the given key as unspent.  The
// output amount of the credit is returned.  It returns without error if no
// credit exists for the key.

// creditIter8ator allows for in-order iteration of all credit records for a
// mined transaction.
//
// Example usage:
//
//   prefix := keyTxRecord(txHash, block)
//   it := makeCreditIterator(ns, prefix)
//   for it.next() {
//           // Use it.elem
//           // If necessary, read additional details from it.ck, it.cv
//   }
//   if it.err != nil {
//           // Handle error
//   }
//
// The elem's Spent field is not set to true if the credit is spent by an
// unmined transaction.  To check for this case:
//
//   k := canonicalOutPoint(&txHash, it.elem.Index)
//   it.elem.Spent = existsRawUnminedInput(ns, k) != nil

//All the relevant output in a block are keyed as such:
//
//    [0:4] Block Height(4 bytes)
//    [4:36] Block Hash (32 bytes)
// the value is identified as such:
//    [0:4] number of relevant transaction output
//      For transaction outpoint
//  		[4:36] transaction hash
//  		[36:37] output index...

func putBlockOutputs(ns walletdb.ReadWriteBucket, blockHeight int32, blockHash chainhash.Hash, outpoints []wire.OutPointAbe) error {
	k := canonicalBlock(blockHeight, blockHash)
	v := make([]byte, 4+len(outpoints)*(chainhash.HashSize+1))
	offset := 0
	byteOrder.PutUint32(v[offset:], uint32(len(outpoints)))
	offset += 4
	for j := 0; j < len(outpoints); j++ {
		copy(v[offset:], outpoints[j].TxHash[:])
		offset += chainhash.HashSize
		v[offset] = outpoints[j].Index
		offset += 1
	}
	err := ns.NestedReadWriteBucket(bucketBlockOutputs).Put(k, v)
	if err != nil {
		str := "failed to put block output"
		return storeError(ErrDatabase, str, err)
	}

	outpoints2, err := fetchBlockOutput(ns, blockHeight, blockHash)
	if err != nil {
		panic("error fetchBlockOutput in putBlockOutputs")
	}

	if len(outpoints) != len(outpoints2) {
		panic("error fetchBlockOutput in putBlockOutputs")
	}
	for i := 0; i < len(outpoints); i++ {
		if !outpoints[i].TxHash.IsEqual(&outpoints2[i].TxHash) || outpoints[i].Index != outpoints2[i].Index {
			panic("error fetchBlockOutput in putBlockOutputs")
		}
	}
	return nil
}

// TODO(abe):integrated function
func fetchBlockOutputWithHeight(ns walletdb.ReadBucket, height int32) ([]byte, []*wire.OutPointAbe, error) {
	k := make([]byte, 36)
	var v []byte
	err := ns.NestedReadBucket(bucketBlockOutputs).ForEach(func(key, value []byte) error {
		h := byteOrder.Uint32(key)
		if h == uint32(height) {
			copy(k, key)
			v = make([]byte, len(value))
			copy(v, value)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if v == nil { // it means that there is zero outputs controlled by wallet in this block
		return nil, nil, nil
	}
	n := byteOrder.Uint32(v[:4])
	if len(v) < int(n*(chainhash.HashSize+1)+4) {
		str := "wrong value in block output bucket"
		return nil, nil, fmt.Errorf(str)
	}
	var res []*wire.OutPointAbe
	offset := 4
	for offset < len(v) {
		tmp := new(wire.OutPointAbe)
		copy(tmp.TxHash[:], v[offset:])
		offset += chainhash.HashSize
		tmp.Index = v[offset] //TODO(abe): if it run with error, maybe there
		offset += 1
		res = append(res, tmp)
	}
	return k, res, nil
}
func fetchBlockOutput(ns walletdb.ReadBucket, blockHeight int32, blockHash chainhash.Hash) ([]*wire.OutPointAbe, error) {
	k := canonicalBlock(blockHeight, blockHash)
	v := ns.NestedReadBucket(bucketBlockOutputs).Get(k)
	if len(v) == 0 {
		return nil, nil
	}

	n := byteOrder.Uint32(v[:4])
	if len(v) < int(4+n*(chainhash.HashSize+1)) {
		str := "wrong value in block output bucket"
		return nil, fmt.Errorf(str)
	}
	var res []*wire.OutPointAbe
	offset := 4
	for offset < len(v) {
		tmp := new(wire.OutPointAbe)
		copy(tmp.TxHash[:], v[offset:])
		offset += chainhash.HashSize
		tmp.Index = v[offset] //TODO(abe): if it run with error, maybe there
		offset += 1
		res = append(res, tmp)
	}
	return res, nil
}
func deleteBlockOutput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockOutputs).Delete(k)
	if err != nil {
		str := "failed to delete block output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// BlockInputs: block height||block hash => [](utxoRing ||[]serialNumbers)
// For the utxoRing, it is before processing the block, and the serialNumber slice
// is the releavant Ring which contains at least one relevant output in this Ring
func valueBlockInput(blockInputs *RingHashSerialNumbers) []byte {
	res := make([]byte, 6)
	totalSize := 6
	// total size(4 bytes) + utxo ring number(2 bytes)
	byteOrder.PutUint16(res[4:6], uint16(len(blockInputs.utxoRings)))
	// total size of block inputs
	for k, v := range blockInputs.utxoRings {
		addedSNs := blockInputs.serialNumbers[k]
		uSize := v.SerializeSize()
		// totoal size (2 bytes)
		// utxo ring size (2 bytes)
		// serialized utxo ring (uSize)
		// added serialNumber numbers (1 byte)
		// [serialNumber...]
		size := 2 + 2 + uSize + 1
		for i := 0; i < len(addedSNs); i++ {
			size += 1 + len(addedSNs[i])
		}
		tmp := make([]byte, size)
		offset := 0
		byteOrder.PutUint16(tmp[offset:offset+2], uint16(size))
		offset += 2
		byteOrder.PutUint16(tmp[offset:offset+2], uint16(uSize))
		offset += 2
		copy(tmp[offset:offset+uSize], v.Serialize()[:])
		offset += uSize
		tmp[offset] = uint8(len(addedSNs))
		offset += 1
		for j := 0; j < len(addedSNs); j++ {
			tmp[offset] = byte(len(addedSNs[j]))
			offset += 1
			copy(tmp[offset:offset+len(addedSNs[j])], addedSNs[j][:])
			offset += len(addedSNs[j])
		}
		totalSize += offset
		res = append(res, tmp...)
	}
	byteOrder.PutUint32(res[0:4], uint32(totalSize))
	return res
}

func putBlockInputs(ns walletdb.ReadWriteBucket, blockHeight int32, blockHash chainhash.Hash, blockInputs *RingHashSerialNumbers) error {
	k := canonicalBlock(blockHeight, blockHash)
	v := valueBlockInput(blockInputs)
	err := ns.NestedReadWriteBucket(bucketBlockInputs).Put(k, v)
	if err != nil {
		str := "failed to put block input"
		return storeError(ErrDatabase, str, err)
	}

	utxoRings, sns, err := fetchBlockInput(ns, k)
	if err != nil {
		panic("unmatched putBlockInputs/fetchBlockInput")
	}

	if len(utxoRings) != len(blockInputs.utxoRings) {
		panic("unmatched putBlockInputs/fetchBlockInput")
	}
	for i := 0; i < len(utxoRings); i++ {
		utxoRing, ok := blockInputs.utxoRings[utxoRings[i].RingHash]
		if !ok {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].Version, utxoRing.Version) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].RingHash, utxoRing.RingHash) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].TxHashes, utxoRing.TxHashes) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].OutputIndexes, utxoRing.OutputIndexes) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].OriginSerialNumberes, utxoRing.OriginSerialNumberes) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].IsMy, utxoRing.IsMy) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].Spent, utxoRing.Spent) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].GotSerialNumberes, utxoRing.GotSerialNumberes) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(utxoRings[i].PackedFlag, utxoRing.PackedFlag) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}

		serialNumbers, ok := blockInputs.serialNumbers[utxoRings[i].RingHash]
		if !ok {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
		if !reflect.DeepEqual(sns[i], serialNumbers) {
			panic("unmatched putBlockInputs/fetchBlockInput")
		}
	}

	return nil
}

func fetchBlockInput(ns walletdb.ReadWriteBucket, k []byte) ([]*UTXORing, [][][]byte, error) {
	if len(k) < 32 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketBlockInputs, 32, len(k))
		return nil, nil, storeError(ErrData, str, nil)
	}
	v := ns.NestedReadBucket(bucketBlockInputs).Get(k)
	if v == nil {
		return nil, nil, fmt.Errorf("this entry is empty")
	}
	offset := 0
	_ = byteOrder.Uint32(v[offset : offset+4])
	offset += 4
	utxoRingN := int(byteOrder.Uint16(v[offset : offset+2]))
	utxoRings := make([]*UTXORing, utxoRingN)
	serialNs := make([][][]byte, utxoRingN)
	offset += 2
	for i := 0; i < utxoRingN; i++ {
		utxoRings[i] = new(UTXORing)
		_ = int(byteOrder.Uint16(v[offset : offset+2])) //total size
		offset += 2
		uSize := int(byteOrder.Uint16(v[offset : offset+2]))
		offset += 2
		//t:=make([]byte,len(k)+int(size))
		//copy(t[0:len(k)],k)
		//copy(t[len(k):len(v)+len(k)],v[2:size])
		err := utxoRings[i].Deserialize(v[offset : offset+uSize])
		if err != nil {
			return nil, nil, err
		}
		offset += uSize
		addedSNs := int(v[offset])
		serialNs[i] = make([][]byte, addedSNs)
		offset += 1
		for j := 0; j < addedSNs; j++ {
			snLen := int(v[offset])
			offset += 1
			serialNs[i][j] = make([]byte, snLen)
			copy(serialNs[i][j][:], v[offset:offset+snLen])
			offset += snLen
		}
	}
	return utxoRings, serialNs, nil
}
func deleteBlockInput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockInputs).Delete(k)
	if err != nil {
		str := "failed to delete block input"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// block height || block hash -> version + []UnspentTXO 【txhash + index + amount + generationTime + ringhash】
func valueImmatureCoinbaseOutput(immatured map[wire.OutPointAbe]*SpendableTXO) []byte {
	//res := make([]byte, len(immatured)*(32+1+8+8+32))
	unitSize := 4 + 4 + chainhash.HashSize + 1 + 8 + 1 + 8 + PublicRandBytesLen + chainhash.HashSize + 1 + 1
	res := make([]byte, len(immatured)*unitSize) // todo: should not use hard codes. and the version field is the same so it can be optimized
	offset := 0
	for _, utxo := range immatured {
		byteOrder.PutUint32(res[offset:offset+4], utxo.Version)
		offset += 4
		byteOrder.PutUint32(res[offset:offset+4], uint32(utxo.Height))
		offset += 4
		copy(res[offset:offset+chainhash.HashSize], utxo.TxOutput.TxHash[:])
		offset += chainhash.HashSize
		res[offset] = utxo.TxOutput.Index
		offset += 1
		byteOrder.PutUint64(res[offset:offset+8], utxo.Amount)
		offset += 8
		copy(res[offset:offset+PublicRandBytesLen], utxo.PublicRand[:])
		offset += PublicRandBytesLen

		res[offset] = utxo.RingIndex
		offset += 1
		byteOrder.PutUint64(res[offset:offset+8], uint64(utxo.GenerationTime.Unix()))
		offset += 8
		copy(res[offset:offset+chainhash.HashSize], utxo.RingHash[:])
		offset += chainhash.HashSize

		res[offset] = utxo.RingSize
		offset += 1

		res[offset] = byte(utxo.PackedFlag)
		offset += 1
	}
	return res
}

func deserializedImmatureCoinbaseOutput(v []byte) (map[wire.OutPointAbe]*SpendableTXO, error) {
	op := make(map[wire.OutPointAbe]*SpendableTXO)
	unitSize := 4 + 4 + chainhash.HashSize + 1 + 8 + 1 + 8 + PublicRandBytesLen + chainhash.HashSize + 1 + 1
	if len(v)%unitSize != 0 {
		return nil, errors.New("wrong data stored in database for immature coinbase output")
	}
	num := len(v) / unitSize

	offset := 0
	//for i := 0; i < len(v)/(32+1+8+8+32); i++ {
	for i := 0; i < num; i++ { // todo: should not use hardcodes
		tmp := new(SpendableTXO)
		tmp.Version = byteOrder.Uint32(v[offset : offset+4])
		offset += 4
		tmp.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
		offset += 4
		copy(tmp.TxOutput.TxHash[:], v[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize
		tmp.TxOutput.Index = v[offset]
		offset += 1
		tmp.Amount = byteOrder.Uint64(v[offset : offset+8])
		offset += 8
		tmp.PublicRand = make([]byte, PublicRandBytesLen)
		copy(tmp.PublicRand[:], v[offset:offset+PublicRandBytesLen])
		offset += PublicRandBytesLen

		tmp.RingIndex = v[offset]
		offset += 1
		tmp.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
		offset += 8
		copy(tmp.RingHash[:], v[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize

		tmp.RingSize = v[offset]
		offset += 1

		tmp.PackedFlag = txoFlag(v[offset])
		offset += 1

		op[tmp.TxOutput] = tmp
	}
	return op, nil
}
func putImmatureCoinbaseOutput(ns walletdb.ReadWriteBucket, blockHeight int32, blockHash chainhash.Hash, txos map[wire.OutPointAbe]*SpendableTXO) error {
	k := canonicalBlock(blockHeight, blockHash)
	v := valueImmatureCoinbaseOutput(txos)
	err := ns.NestedReadWriteBucket(bucketImmaturedCoinbaseOutput).Put(k, v)
	if err != nil {
		str := "failed to put immature coinbase output"
		return storeError(ErrDatabase, str, err)
	}

	immatureCoinbaseOutput, err := fetchImmatureCoinbaseOutput(ns, blockHeight, blockHash)
	if err != nil {
		panic("unmatched ImmatureCoinbaseOutputs")
	}
	for outpoint, txo := range txos {
		txo2, ok := immatureCoinbaseOutput[outpoint]
		if !ok {
			panic("unmatched ImmatureCoinbaseOutputs")
		}
		if !reflect.DeepEqual(txo, txo2) {
			panic("unmatched ImmatureCoinbaseOutputs")
		}
	}

	for outpoint, txo := range immatureCoinbaseOutput {
		txo2, ok := txos[outpoint]
		if !ok {
			panic("unmatched ImmatureCoinbaseOutputs")
		}
		if !reflect.DeepEqual(txo, txo2) {
			panic("unmatched ImmatureCoinbaseOutputs")
		}
	}

	return nil
}
func fetchImmatureCoinbaseOutput(ns walletdb.ReadBucket, height int32, hash chainhash.Hash) (map[wire.OutPointAbe]*SpendableTXO, error) {
	k := canonicalBlock(height, hash)
	v := ns.NestedReadBucket(bucketImmaturedCoinbaseOutput).Get(k)
	if len(v) == 0 {
		return nil, nil
	}
	return deserializedImmatureCoinbaseOutput(v)
}

func existsRawImmatureCoinbaseOutput(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketImmaturedCoinbaseOutput).Get(k)
}

func deleteImmatureCoinbaseOutput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketImmaturedCoinbaseOutput).Delete(k)
	if err != nil {
		str := "failed to delete immature coinbase output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// block height || block hash -> []UnspentTXO 【txhash + index + amount + generationTime + ringhash + application_flags 】
func valueImmatureOutput(immatureTxo map[wire.OutPointAbe]*SpendableTXO) []byte {
	//res := make([]byte, len(immatureTxo)*(32+1+8+8+32))
	unitSize := 4 + 4 + chainhash.HashSize + 1 + 8 + 1 + 8 + PublicRandBytesLen + chainhash.HashSize + 1 + 1
	res := make([]byte, len(immatureTxo)*unitSize) // todo: should not use hard code
	offset := 0
	for _, utxo := range immatureTxo {
		byteOrder.PutUint32(res[offset:offset+4], utxo.Version)
		offset += 4
		byteOrder.PutUint32(res[offset:offset+4], uint32(utxo.Height))
		offset += 4
		copy(res[offset:offset+chainhash.HashSize], utxo.TxOutput.TxHash[:])
		offset += chainhash.HashSize
		res[offset] = utxo.TxOutput.Index
		offset += 1
		byteOrder.PutUint64(res[offset:offset+8], utxo.Amount)
		offset += 8
		copy(res[offset:offset+PublicRandBytesLen], utxo.PublicRand[:])
		offset += PublicRandBytesLen

		res[offset] = utxo.RingIndex
		offset += 1
		byteOrder.PutUint64(res[offset:offset+8], uint64(utxo.GenerationTime.Unix()))
		offset += 8
		copy(res[offset:offset+chainhash.HashSize], utxo.RingHash[:])
		offset += chainhash.HashSize

		res[offset] = utxo.RingSize
		offset += 1

		res[offset] = byte(utxo.PackedFlag)
		offset += 1
	}
	return res
}
func deserializedImmatureOutput(v []byte) (map[wire.OutPointAbe]*SpendableTXO, error) {
	op := make(map[wire.OutPointAbe]*SpendableTXO)
	unitSize := 4 + 4 + chainhash.HashSize + 1 + 8 + 1 + 8 + PublicRandBytesLen + chainhash.HashSize + 1 + 1
	if len(v)%unitSize != 0 {
		return nil, errors.New("wrong data stored in database for immature output")
	}
	num := len(v) / unitSize

	offset := 0
	//	for i := 0; i < len(v)/(32+1+8+8+32); i++ {
	for i := 0; i < num; i++ { // todo: should not use hard code, should use getXXXSize
		tmp := new(SpendableTXO)
		tmp.Version = byteOrder.Uint32(v[offset : offset+4])
		offset += 4
		tmp.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
		offset += 4
		copy(tmp.TxOutput.TxHash[:], v[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize
		tmp.TxOutput.Index = v[offset]
		offset += 1
		tmp.Amount = byteOrder.Uint64(v[offset : offset+8])
		offset += 8
		tmp.PublicRand = make([]byte, PublicRandBytesLen)
		copy(tmp.PublicRand[:], v[offset:offset+PublicRandBytesLen])
		offset += PublicRandBytesLen

		tmp.RingIndex = v[offset]
		offset += 1
		tmp.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
		offset += 8
		copy(tmp.RingHash[:], v[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize

		tmp.RingSize = v[offset]
		offset += 1

		tmp.PackedFlag = txoFlag(v[offset])
		offset += 1

		op[tmp.TxOutput] = tmp
	}
	return op, nil
}
func putImmatureOutput(ns walletdb.ReadWriteBucket, blockHeight int32, blockHash chainhash.Hash, txos map[wire.OutPointAbe]*SpendableTXO) error {
	k := canonicalBlock(blockHeight, blockHash)
	v := valueImmatureOutput(txos)
	err := ns.NestedReadWriteBucket(bucketImmaturedOutput).Put(k, v)
	if err != nil {
		str := "failed to put immature output"
		return storeError(ErrDatabase, str, err)
	}

	immatureOutput, err := fetchImmatureOutput(ns, blockHeight, blockHash)
	if err != nil {
		panic("unmatched fetchImmatureOutput")
	}
	for outpoint, txo := range txos {
		txo2, ok := immatureOutput[outpoint]
		if !ok {
			panic("unmatched fetchImmatureOutput")
		}
		if !reflect.DeepEqual(txo2.Version, txo.Version) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.Height, txo.Height) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.TxOutput, txo.TxOutput) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.PackedFlag, txo.PackedFlag) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.Amount, txo.Amount) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.PublicRand, txo.PublicRand) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.GenerationTime, txo.GenerationTime) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.RingHash, txo.RingHash) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.RingSize, txo.RingSize) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.RingIndex, txo.RingIndex) {
			panic("putImmatureOutput unmatched")
		}
	}

	for outpoint, txo := range immatureOutput {
		txo2, ok := txos[outpoint]
		if !ok {
			panic("unmatched fetchImmatureOutput")
		}
		if !reflect.DeepEqual(txo2.Version, txo.Version) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.Height, txo.Height) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.TxOutput, txo.TxOutput) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.PackedFlag, txo.PackedFlag) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.Amount, txo.Amount) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.PublicRand, txo.PublicRand) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.GenerationTime, txo.GenerationTime) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.RingHash, txo.RingHash) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.RingSize, txo.RingSize) {
			panic("putImmatureOutput unmatched")
		}
		if !reflect.DeepEqual(txo2.RingIndex, txo.RingIndex) {
			panic("putImmatureOutput unmatched")
		}
	}

	return nil
}
func fetchImmatureOutput(ns walletdb.ReadBucket, height int32, hash chainhash.Hash) (map[wire.OutPointAbe]*SpendableTXO, error) {
	k := canonicalBlock(height, hash)
	v := ns.NestedReadBucket(bucketImmaturedOutput).Get(k)
	if len(v) == 0 {
		return nil, nil
	}
	return deserializedImmatureOutput(v)
}

func deleteImmatureOutput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketImmaturedOutput).Delete(k)
	if err != nil {
		str := "failed to delete immature output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func putSpendableTXO(ns walletdb.ReadWriteBucket, txo *SpendableTXO) error {
	k := canonicalOutPointAbe(txo.TxOutput.TxHash, txo.TxOutput.Index)
	v, err := txo.Serialize()
	if err != nil {
		return err
	}
	err = ns.NestedReadWriteBucket(bucketMaturedOutput).Put(k, v)
	if err != nil {
		str := "failed to put unspent output"
		return storeError(ErrDatabase, str, err)
	}

	spendableTXO, err := fetchSpendableTXO(ns, txo.TxOutput.TxHash, txo.TxOutput.Index)
	if err != nil {
		panic("SpendableTXO has unmatched serialization/deserialization ")
	}
	if !reflect.DeepEqual(txo, spendableTXO) {
		panic("SpendableTXO has unmatched serialization/deserialization ")
	}
	return nil
}
func fetchSpendableTXO(ns walletdb.ReadBucket, hash chainhash.Hash, index uint8) (*SpendableTXO, error) {
	k := canonicalOutPointAbe(hash, index)
	v := ns.NestedReadBucket(bucketMaturedOutput).Get(k)
	if len(v) == 0 {
		return nil, nil
	}
	op := new(SpendableTXO)
	err := op.Deserialize(&wire.OutPointAbe{TxHash: hash, Index: index}, v)
	return op, err
}
func existsSpendableTXO(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketMaturedOutput).Get(k)
}
func deleteSpendableTXO(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketMaturedOutput).Delete(k)
	if err != nil {
		str := "failed to delete unspent output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// UnspentTXO: store the relevant output which is unspent by current wallet
// its key is transaction hash with the output index
// its value is relevant information : From height,Fromcoinbase|isAUTCoin,amount,generation time, rinhash
func putUnconfirmedTXO(ns walletdb.ReadWriteBucket, sbuTxo *UnconfirmedTXO) error {
	k := canonicalOutPointAbe(sbuTxo.TxOutput.TxHash, sbuTxo.TxOutput.Index)
	v, err := sbuTxo.Serialize()
	if err != nil {
		return err
	}

	err = ns.NestedReadWriteBucket(bucketSpentButUnmined).Put(k, v)
	if err != nil {
		str := "failed to put spent but unmined output"
		return storeError(ErrDatabase, str, err)
	}

	txo, err := fetchUnconfirmedTXO(ns, sbuTxo.TxOutput.TxHash, sbuTxo.TxOutput.Index)
	if err != nil {
		panic("putUnconfirmedTXO has unmatched serialization/deserialization ")
	}
	if !reflect.DeepEqual(sbuTxo.SpendableTXO, txo.SpendableTXO) {
		panic("putUnconfirmedTXO has unmatched serialization/deserialization ")
	}
	if !reflect.DeepEqual(sbuTxo.SpentByHash, txo.SpentByHash) {
		panic("putUnconfirmedTXO has unmatched serialization/deserialization ")
	}
	return nil
}
func fetchUnconfirmedTXO(ns walletdb.ReadBucket, hash chainhash.Hash, index uint8) (*UnconfirmedTXO, error) {
	k := canonicalOutPointAbe(hash, index)
	v := ns.NestedReadBucket(bucketSpentButUnmined).Get(k)
	if len(v) == 0 {
		return nil, nil
	}
	sbu := new(UnconfirmedTXO)
	err := sbu.Deserialize(&wire.OutPointAbe{
		TxHash: hash,
		Index:  index,
	}, v)
	return sbu, err
}
func existsUnconfirmedTXO(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketSpentButUnmined).Get(k)
}
func deleteUnconfirmedTXO(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketSpentButUnmined).Delete(k)
	if err != nil {
		str := "failed to delete spent but unmined output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// ConfirmedTXO: store the relevant output which is spent by current wallet and now is contained in a block
// its key is transaction hash with the output index
// its value is relevant information : height,From coinbase,amount,generation time, rinhash,serialNumber，spentTime,confirmedTime
func putConfirmedTXO(ns walletdb.ReadWriteBucket, scTxo *ConfirmedTXO) error {
	k := canonicalOutPointAbe(scTxo.TxOutput.TxHash, scTxo.TxOutput.Index)
	v, err := scTxo.Serialize()
	if err != nil {
		return err
	}

	err = ns.NestedReadWriteBucket(bucketSpentConfirmed).Put(k, v)
	if err != nil {
		str := "failed to put spent and confirmed output"
		return storeError(ErrDatabase, str, err)
	}

	txo, err := fetchConfirmedTXO(ns, scTxo.TxOutput.TxHash, scTxo.TxOutput.Index)
	if err != nil {
		panic("SpendableTXO has unmatched serialization/deserialization ")
	}
	if !reflect.DeepEqual(txo.SpendableTXO, scTxo.SpendableTXO) {
		panic("SpendableTXO has unmatched serialization/deserialization ")
	}
	if !reflect.DeepEqual(txo.SpentByHash, scTxo.SpentByHash) {
		panic("SpendableTXO has unmatched serialization/deserialization ")
	}
	if !reflect.DeepEqual(txo.ConfirmedByBlockHash, scTxo.ConfirmedByBlockHash) {
		panic("SpendableTXO has unmatched serialization/deserialization ")
	}

	return nil
}
func fetchConfirmedTXO(ns walletdb.ReadWriteBucket, hash chainhash.Hash, index uint8) (*ConfirmedTXO, error) {
	k := canonicalOutPointAbe(hash, index)
	v := ns.NestedReadBucket(bucketSpentConfirmed).Get(k)
	if len(v) == 0 {
		return nil, nil
	}
	sct := new(ConfirmedTXO)
	err := sct.Deserialize(&wire.OutPointAbe{
		TxHash: hash,
		Index:  index,
	}, v)
	if err != nil {
		return nil, err
	}

	return sct, nil
}
func deleteConfirmedTXO(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketSpentConfirmed).Delete(k)
	if err != nil {
		str := "failed to delete spent and confirmed output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func ConfirmSpentTXO(ns walletdb.ReadWriteBucket, txHash chainhash.Hash, index uint8, spentTxHash chainhash.Hash, confirmedByBlockHash chainhash.Hash) error {
	k := canonicalOutPointAbe(txHash, index)
	balance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpendableBalance(ns)
	if err != nil {
		return err
	}

	ctautRootCoinNums, err := fetchCTAUTRootCoinNum(ns)
	if err != nil {
		return err
	}
	ctautSpendableRootCoinNums, err := fetchCTAUTSpenableRootCoinNum(ns)
	if err != nil {
		return err
	}
	ctautBals, err := fetchCTAUTMinedBalance(ns)
	if err != nil {
		return err
	}
	ctautSpendableBals, err := fetchCTAUTSpenableBalance(ns)
	if err != nil {
		return err
	}

	scTxo := &ConfirmedTXO{}

	// if this output is in unspent txo bucket
	if utxo, err := fetchSpendableTXO(ns, txHash, index); err == nil { //from the MaturedOutput
		//otherwise it has been moved to spentButUnmined bucket
		// update the balances
		amt := abeutil.Amount(utxo.Amount)
		balance -= amt
		spendableBal -= amt
		err = deleteSpendableTXO(ns, k)
		if err != nil {
			return err
		}
		scTxo.SpendableTXO = *utxo
		scTxo.SpentByHash = spentTxHash
		scTxo.SpentTime = time.Now()
		scTxo.ConfirmedByBlockHash = confirmedByBlockHash
		scTxo.ConfirmTime = time.Now()

		if utxo.IsCTAUTCoin() {
			token, err := fetchRawCTAUTCoin(ns, utxo.TxOutput.TxHash, utxo.TxOutput.Index)
			if err != nil {
				return err
			}
			if token.IsAUTRootCoin {
				ctautSpendableRootCoinNums[token.AUTIdentifier.String()] -= 1
				ctautRootCoinNums[token.AUTIdentifier.String()] -= 1
			} else {
				ctautSpendableBals[token.AUTIdentifier.String()] -= token.Value
				ctautBals[token.AUTIdentifier.String()] -= token.Value
			}
		}

	} else if sbuTxo, err := fetchUnconfirmedTXO(ns, txHash, index); err == nil { //from the spentButUnmined bucket
		amt := abeutil.Amount(sbuTxo.Amount)
		balance -= amt
		err = deleteUnconfirmedTXO(ns, k)
		if err != nil {
			return err
		}

		scTxo.UnconfirmedTXO = *sbuTxo
		if !scTxo.UnconfirmedTXO.SpentByHash.IsEqual(&spentTxHash) {
			scTxo.SpentByHash = spentTxHash
			scTxo.SpentTime = time.Now()
		}
		scTxo.ConfirmedByBlockHash = confirmedByBlockHash
		scTxo.ConfirmTime = time.Now()

		if sbuTxo.IsCTAUTCoin() {
			token, err := fetchRawCTAUTCoin(ns, sbuTxo.TxOutput.TxHash, sbuTxo.TxOutput.Index)
			if err != nil {
				return err
			}
			if token.IsAUTRootCoin {
				ctautRootCoinNums[token.AUTIdentifier.String()] -= 1
			} else {
				ctautBals[token.AUTIdentifier.String()] -= token.Value
			}
		}
	} else {
		log.Errorf("can not find txo (%s,%d) in confirmed bucker or unconfirmed bucket", txHash, index)
		return fmt.Errorf("can not find txo (%s,%d)", txHash, index)
	}
	// update confirm bucket
	err = putConfirmedTXO(ns, scTxo)
	if err != nil {
		return err
	}
	err = putSpendableBalance(ns, spendableBal)
	if err != nil {
		return err
	}
	err = putMinedBalance(ns, balance)
	if err != nil {
		return err
	}
	err = putCTAUTRootCoinNum(ns, ctautRootCoinNums)
	if err != nil {
		return err
	}
	err = putCTAUTSpenableRootCoinNum(ns, ctautSpendableRootCoinNums)
	if err != nil {
		return err
	}
	err = putCTAUTMinedBalance(ns, ctautBals)
	if err != nil {
		return err
	}
	err = putCTAUTSpenableBalance(ns, ctautSpendableBals)
	if err != nil {
		return err
	}

	return nil
}

// All the relevant UTXORing are keyed as such:
//
//	[0:32] RingHash(32 bytes)
//	value see the serialize method of Ring
func putRingDetails(ns walletdb.ReadWriteBucket, ringHash chainhash.Hash, ring *Ring) error {
	err := ns.NestedReadWriteBucket(bucketRingDetails).Put(ringHash[:], ring.Serialize())
	if err != nil {
		str := "failed to put ring details"
		return storeError(ErrDatabase, str, err)
	}

	res, err := fetchRingDetails(ns, ringHash[:])
	if err != nil || !reflect.DeepEqual(ring, res) {
		panic("putRingDetails has unmatched serialization/deserialization ")
	}

	return nil
}
func existsRingDetails(ns walletdb.ReadBucket, hash chainhash.Hash) (k, v []byte) {
	copy(k[:], hash[:])
	v = ns.NestedReadBucket(bucketRingDetails).Get(k)
	return
}
func fetchRingDetails(ns walletdb.ReadBucket, k []byte) (*Ring, error) {
	v := ns.NestedReadBucket(bucketRingDetails).Get(k)
	if v == nil {
		return nil, fmt.Errorf("the pair is not exist")
	}
	res := new(Ring)
	err := res.Deserialize(v)
	return res, err
}
func FetchRingDetails(ns walletdb.ReadBucket, k []byte) (*Ring, error) {
	return fetchRingDetails(ns, k)
}
func deleteRingDetails(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketRingDetails).Delete(k)
	if err != nil {
		str := "failed to delete ring details"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func updateDeletedHeightRingDetails(ns walletdb.ReadWriteBucket, ringHash chainhash.Hash, height int32) error {
	ring, err := fetchRingDetails(ns, ringHash[:])
	if err != nil {
		str := "failed to fetch ring details"
		return storeError(ErrDatabase, str, err)
	}
	ring.BlockHeight = height
	err = putRingDetails(ns, ringHash, ring)
	if err != nil {
		return err
	}
	return nil
}

// All the relevant ring are keyed as such:
//
//	[0:32] RingHash(32 bytes)
//	value see the serialize method of UTXORing
func valueUTXORing(u *UTXORing) []byte {
	return u.Serialize()[:]
}
func existsUTXORing(ns walletdb.ReadBucket, hash chainhash.Hash) (k, v []byte) {
	k = make([]byte, 32)
	copy(k[:], hash[:])
	v = ns.NestedReadBucket(bucketUTXORing).Get(k)
	return
}
func putUTXORing(ns walletdb.ReadWriteBucket, ringHash chainhash.Hash, utxoring *UTXORing) error {
	k := ringHash[:]
	v := utxoring.Serialize()[:]

	err := ns.NestedReadWriteBucket(bucketUTXORing).Put(k, v)
	if err != nil {
		str := "failed to put utxoring"
		return storeError(ErrDatabase, str, err)
	}

	res, err := fetchUTXORing(ns, k)
	if err != nil || !reflect.DeepEqual(utxoring, res) {
		panic("UTXORing has unmatched serialization/deserialization ")
	}

	return nil
}
func fetchUTXORing(ns walletdb.ReadBucket, k []byte) (*UTXORing, error) {
	v := ns.NestedReadBucket(bucketUTXORing).Get(k)
	if v == nil {
		return nil, nil
	}
	res := new(UTXORing)
	err := res.Deserialize(v)
	return res, err
}
func deleteUTXORing(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketUTXORing).Delete(k)
	if err != nil {
		str := "failed to delete utxoring"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// The unspent index records all outpoints for mined credits which are not spent
// by any other mined transaction records (but may be spent by a mempool
// transaction).
//
// Keys are use the canonical outpoint serialization:
//
//   [0:32]  Transaction hash (32 bytes)
//   [32:36] Output index (4 bytes)
//
// Values are serialized as such:
//
//   [0:4]   Block height (4 bytes)
//   [4:36]  Block hash (32 bytes)

func readUnspentBlock(v []byte, block *Block) error {
	if len(v) < 36 {
		str := "short unspent value"
		return storeError(ErrData, str, nil)
	}
	block.Height = int32(byteOrder.Uint32(v))
	copy(block.Hash[:], v[4:36])
	return nil
}

// existsUnspent returns the key for the unspent output and the corresponding
// key for the credits bucket.  If there is no unspent output recorded, the
// credit key is nil.

// existsRawUnspent returns the credit key if there exists an output recorded
// for the raw unspent key.  It returns nil if the k/v pair does not exist.

// All transaction debits (inputs which spend credits) are keyed as such:
//
//   [0:32]  Transaction hash (32 bytes)
//   [32:36] Block height (4 bytes)
//   [36:68] Block hash (32 bytes)
//   [68:72] Input index (4 bytes)
//
// The first 68 bytes match the key for the transaction record and may be used
// as a prefix filter to iterate through all debits in order.
//
// The debit value is serialized as such:
//
//   [0:8]   Amount (8 bytes)
//   [8:80]  Credits bucket key (72 bytes)
//             [8:40]  Transaction hash (32 bytes)
//             [40:44] Block height (4 bytes)
//             [44:76] Block hash (32 bytes)
//             [76:80] Output index (4 bytes)

// existsDebit checks for the existance of a debit.  If found, the debit and
// previous credit keys are returned.  If the debit does not exist, both keys
// are nil.

// debitIterator allows for in-order iteration of all debit records for a
// mined transaction.
//
// Example usage:
//
//   prefix := keyTxRecord(txHash, block)
//   it := makeDebitIterator(ns, prefix)
//   for it.next() {
//           // Use it.elem
//           // If necessary, read additional details from it.ck, it.cv
//   }
//   if it.err != nil {
//           // Handle error
//   }

// All unmined transactions are saved in the unmined bucket keyed by the
// transaction hash.  The value matches that of mined transaction records:
//
//   [0:8]   Received time (8 bytes)
//   [8:]    Serialized transaction (varies)

func putTxRecord(ns walletdb.ReadWriteBucket, bucketName []byte, tx *TxRecord) error {
	k := tx.Hash[:]
	v, err := tx.Serialize()
	if err != nil {
		return err
	}

	res := new(TxRecord)
	err = res.Deserialize(v)
	if err != nil {
		panic("unmatched TxRecord Serialized/Deserialized")
	}
	if !reflect.DeepEqual(res, tx) {
		panic("unmatched TxRecord Serialized/Deserialized")
	}

	err = ns.NestedReadWriteBucket(bucketName).Put(k, v)
	if err != nil {
		str := "fail to put unconfirmed transaction"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func putUnconfirmedTx(ns walletdb.ReadWriteBucket, tx *TxRecord) error {
	err := putTxRecord(ns, bucketUnconfirmedTx, tx)
	if err != nil {
		return err
	}
	return nil
}
func putInvalidTx(ns walletdb.ReadWriteBucket, tx *TxRecord) error {
	err := putTxRecord(ns, bucketInvalidTx, tx)
	if err != nil {
		return err
	}
	return nil
}
func putConfirmedTx(ns walletdb.ReadWriteBucket, tx *TxRecord) error {
	err := putTxRecord(ns, bucketConfirmedTx, tx)
	if err != nil {
		return err
	}
	return nil
}

func putRawUnconfirmedTx(ns walletdb.ReadWriteBucket, k, v []byte) error {
	// update the update time
	newBytes := make([]byte, 8, len(v))
	byteOrder.PutUint64(newBytes, uint64(time.Now().Unix()))
	newBytes = append(newBytes, v[8:]...)
	err := ns.NestedReadWriteBucket(bucketUnconfirmedTx).Put(k, newBytes)
	if err != nil {
		str := "fail to put unconfirmed transaction"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func putRawInvalidTx(ns walletdb.ReadWriteBucket, k, v []byte) error {
	// update the update time
	newBytes := make([]byte, 8, len(v))
	byteOrder.PutUint64(newBytes, uint64(time.Now().Unix()))
	newBytes = append(newBytes, v[8:]...)
	err := ns.NestedReadWriteBucket(bucketInvalidTx).Put(k, newBytes)
	if err != nil {
		str := "fail to put invalid transaction"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func putRawConfirmedTx(ns walletdb.ReadWriteBucket, k, v []byte) error {
	// Do not update the time, because confirm transaction just be put by receiving block
	err := ns.NestedReadWriteBucket(bucketConfirmedTx).Put(k, v)
	if err != nil {
		str := "fail to put confirmed transaction"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func putRawRelevantTxs(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketRelevantTxs).Put(k, v)
	if err != nil {
		str := "fail to put relevant transactions"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func existsRawUnconfirmedTx(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketUnconfirmedTx).Get(k)
}
func existsRawInvalidTx(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketInvalidTx).Get(k)
}
func existsRawConfirmedTx(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketConfirmedTx).Get(k)
}
func existsRawReleventTxs(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketRelevantTxs).Get(k)
}

func DeleteRawUnmined(ns walletdb.ReadWriteBucket, tx *wire.MsgTxAbe) error {
	for _, input := range tx.TxIns {
		ringHash := input.PreviousOutPointRing.Hash()

		utxoRing, err := fetchUTXORing(ns, ringHash[:])
		if err != nil {
			log.Errorf("fail to fetch UTXO Ring from bucket")
			continue
		}
		if utxoRing == nil {
			continue
		}
		for idx, sn := range utxoRing.OriginSerialNumberes {
			if bytes.Equal(sn, input.SerialNumber) {
				k := canonicalOutPointAbe(utxoRing.TxHashes[idx], utxoRing.OutputIndexes[idx])
				sbuTxo, err := fetchUnconfirmedTXO(ns, utxoRing.TxHashes[idx], utxoRing.OutputIndexes[idx])
				if err != nil {
					err = errors.New("can not find unconfirmed txo in unconfirmed txo bucket")
					log.Errorf("can not move unconfirmed txo to matured txo due to error:%s in DeleteRawUnmined", err)
					return err
				}
				if err = deleteUnconfirmedTXO(ns, k); err != nil {
					log.Errorf("can not move unconfirmed txo to matured txo due to error:%s in DeleteRawUnmined", err)
					return err
				}

				if sbuTxo != nil {
					if err = putSpendableTXO(ns, &sbuTxo.SpendableTXO); err != nil {
						log.Errorf("can not move unconfirmed txo to matured txo due to error:%s in DeleteRawUnmined", err)
						return err
					}
				}
				break
			}
		}
	}
	txHash := tx.TxHash()
	return deleteRawUnconfirmedTx(ns, txHash[:])
}

// TODO(abe):when delete the entry in unminedAbe, it must explicit where the corresponding entry in spent but unmined into
//
//	SpentAndConfirm or UnspentTXO bucket?
func deleteRawUnconfirmedTx(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketUnconfirmedTx).Delete(k)
	if err != nil {
		str := "failed to delete unconfirmed transaction record"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func deleteRawInvalidTx(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketInvalidTx).Delete(k)
	if err != nil {
		str := "failed to delete invalid transaction record"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func deleteRawConfirmedTx(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketConfirmedTx).Delete(k)
	if err != nil {
		str := "failed to delete confirmed transaction record"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// Unmined transaction credits use the canonical serialization format:
//
//  [0:32]   Transaction hash (32 bytes)
//  [32:36]  Output index (4 bytes)
//
// The value matches the format used by mined credits, but the spent flag is
// never set and the optional debit record is never included.  The simplified
// format is thus:
//
//   [0:8]   Amount (8 bytes)
//   [8]     Flags (1 byte)
//             0x02: Change

// unminedCreditIterator allows for cursor iteration over all credits, in order,
// from a single unmined transaction.
//
//  Example usage:
//
//   it := makeUnminedCreditIterator(ns, txHash)
//   for it.next() {
//           // Use it.elem, it.ck and it.cv
//           // Optionally, use it.delete() to remove this k/v pair
//   }
//   if it.err != nil {
//           // Handle error
//   }
//
// The spentness of the credit is not looked up for performance reasons (because
// for unspent credits, it requires another lookup in another bucket).  If this
// is needed, it may be checked like this:
//
//   spent := existsRawUnminedInput(ns, it.ck) != nil

type readCursor struct {
	walletdb.ReadCursor
}

func (r readCursor) Delete() error {
	str := "failed to delete current cursor item from read-only cursor"
	return storeError(ErrDatabase, str, walletdb.ErrTxNotWritable)
}

// unavailable until https://github.com/boltdb/bolt/issues/620 is fixed.
// func (it *unminedCreditIterator) delete() error {
// 	err := it.c.Delete()
// 	if err != nil {
// 		str := "failed to delete unmined credit"
// 		return storeError(ErrDatabase, str, err)
// 	}
// 	return nil
// }

// Outpoints spent by unmined transactions are saved in the unmined inputs
// bucket.  This bucket maps between each previous output spent, for both mined
// and unmined transactions, to the hash of the unmined transaction.
//
// The key is serialized as such:
//
//   [0:32]   Transaction hash (32 bytes)
//   [32:36]  Output index (4 bytes)
//
// The value is serialized as such:
//
//   [0:32]   Transaction hash (32 bytes)

// putRawUnminedInput maintains a list of unmined transaction hashes that have
// spent an outpoint. Each entry in the bucket is keyed by the outpoint being
// spent.

// fetchUnminedInputSpendTxHashes fetches the list of unmined transactions that
// spend the serialized outpoint.

// deleteRawUnminedInput removes a spending transaction entry from the list of
// spending transactions for a given input.

// serializeLockedOutput serializes the value of a locked output.
func serializeLockedOutput(id LockID, expiry time.Time) []byte {
	var v [len(id) + 8]byte
	copy(v[:len(id)], id[:])
	byteOrder.PutUint64(v[len(id):], uint64(expiry.Unix()))
	return v[:]
}

// deserializeLockedOutput deserializes the value of a locked output.
func deserializeLockedOutput(v []byte) (LockID, time.Time) {
	var id LockID
	copy(id[:], v[:len(id)])
	expiry := time.Unix(int64(byteOrder.Uint64(v[len(id):])), 0)
	return id, expiry
}

// isLockedOutput determines whether an output is locked. If it is, its assigned
// ID is returned, along with its absolute expiration time. If the output lock
// exists, but its expiration has been met, then the output is considered
// unlocked.
func isLockedOutput(ns walletdb.ReadBucket, op wire.OutPointAbe,
	timeNow time.Time) (LockID, time.Time, bool) {

	// The bucket may not exist, indicating that no outputs have ever been
	// locked, so we can just return now.
	lockedOutputs := ns.NestedReadBucket(bucketLockedOutputs)
	if lockedOutputs == nil {
		return LockID{}, time.Time{}, false
	}

	// Retrieve the output lock, if any, and extract the relevant fields.
	k := canonicalOutPointAbe(op.TxHash, op.Index)
	v := lockedOutputs.Get(k)
	if v == nil {
		return LockID{}, time.Time{}, false
	}
	lockID, expiry := deserializeLockedOutput(v)

	// If the output lock has already expired, delete it now.
	if !timeNow.Before(expiry) {
		return LockID{}, time.Time{}, false
	}

	return lockID, expiry, true
}

// lockOutput creates a lock for `duration` over an output assigned to the `id`,
// preventing it from becoming eligible for coin selection.
func lockOutput(ns walletdb.ReadWriteBucket, id LockID, op wire.OutPointAbe,
	expiry time.Time) error {

	// Create the corresponding bucket if necessary.
	lockedOutputs, err := ns.CreateBucketIfNotExists(bucketLockedOutputs)
	if err != nil {
		str := "failed to create locked outputs bucket"
		return storeError(ErrDatabase, str, err)
	}

	// Store a mapping of outpoint -> (id, expiry).
	k := canonicalOutPointAbe(op.TxHash, op.Index)
	v := serializeLockedOutput(id, expiry)

	if err := lockedOutputs.Put(k, v[:]); err != nil {
		str := fmt.Sprintf("%s: put failed for %v", bucketLockedOutputs,
			op)
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// unlockOutput removes a lock over an output, making it eligible for coin
// selection if still unspent.
func unlockOutput(ns walletdb.ReadWriteBucket, op wire.OutPointAbe) error {
	// The bucket may not exist, indicating that no outputs have ever been
	// locked, so we can just return now.
	lockedOutputs := ns.NestedReadWriteBucket(bucketLockedOutputs)
	if lockedOutputs == nil {
		return nil
	}

	// Delete the key-value pair representing the output lock.
	k := canonicalOutPointAbe(op.TxHash, op.Index)
	if err := lockedOutputs.Delete(k); err != nil {
		str := fmt.Sprintf("%s: delete failed for %v",
			bucketLockedOutputs, op)
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// forEachLockedOutput iterates over all existing locked outputs and invokes the
// callback `f` for each.
func forEachLockedOutput(ns walletdb.ReadBucket,
	f func(wire.OutPointAbe, LockID, time.Time)) error {

	// The bucket may not exist, indicating that no outputs have ever been
	// locked, so we can just return now.
	lockedOutputs := ns.NestedReadBucket(bucketLockedOutputs)
	if lockedOutputs == nil {
		return nil
	}

	return lockedOutputs.ForEach(func(k, v []byte) error {
		var op wire.OutPointAbe
		if err := readCanonicalOutPointAbe(k, &op); err != nil {
			return err
		}
		lockID, expiry := deserializeLockedOutput(v)

		f(op, lockID, expiry)

		return nil
	})
}

// openStore opens an existing transaction store from the passed namespace.
func openStore(ns walletdb.ReadBucket) error {
	version, err := fetchVersion(ns)
	if err != nil {
		return err
	}

	latestVersion := getLatestVersion()
	if version < latestVersion {
		str := fmt.Sprintf("a database upgrade is required to upgrade "+
			"wtxmgr from recorded version %d to the latest version %d",
			version, latestVersion)
		return storeError(ErrNeedsUpgrade, str, nil)
	}

	if version > latestVersion {
		str := fmt.Sprintf("version recorded version %d is newer that "+
			"latest understood version %d", version, latestVersion)
		return storeError(ErrUnknownVersion, str, nil)
	}

	return nil
}

// createStore creates the tx store (with the latest db version) in the passed
// namespace.  If a store already exists, ErrAlreadyExists is returned.
func createStore(ns walletdb.ReadWriteBucket) error {
	// Ensure that nothing currently exists in the namespace bucket.
	ck, cv := ns.ReadCursor().First()
	if ck != nil || cv != nil {
		const str = "namespace is not empty"
		return storeError(ErrAlreadyExists, str, nil)
	}

	// Write the latest store version.
	if err := putVersion(ns, getLatestVersion()); err != nil {
		return err
	}

	// Save the creation date of the store.
	var v [8]byte
	byteOrder.PutUint64(v[:], uint64(time.Now().Unix()))
	err := ns.Put(rootCreateDate, v[:])
	if err != nil {
		str := "failed to store database creation time"
		return storeError(ErrDatabase, str, err)
	}

	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootMinedBalance, v[:])
	if err != nil {
		str := "failed to write zero balance"
		return storeError(ErrDatabase, str, err)
	}
	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootSpendableBalance, v[:])
	if err != nil {
		str := "failed to write zero spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootImmatureCoinbaseBalance, v[:])
	if err != nil {
		str := "failed to write zero spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootImmatureTransferBalance, v[:])
	if err != nil {
		str := "failed to write zero spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootUnconfirmedBalance, v[:])
	if err != nil {
		str := "failed to write zero spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootFreezedBalance, v[:])
	if err != nil {
		str := "failed to write zero freezed balance"
		return storeError(ErrDatabase, str, err)
	}

	// Finally, create all of our required descendant buckets.
	return createBuckets(ns)
}

// createBuckets creates all of the descendants buckets required for the
// transaction store to properly carry its duties.
func createBuckets(ns walletdb.ReadWriteBucket) error {
	if _, err := ns.CreateBucket(bucketLockedOutputs); err != nil {
		str := "failed to create locked outputs bucket"
		return storeError(ErrDatabase, str, err)
	}
	//TODO(abe): change the name of bucket
	if _, err := ns.CreateBucket(bucketBlocks); err != nil {
		str := "failed to create block bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketBlockInputs); err != nil {
		str := "failed to create block input bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketBlockOutputs); err != nil {
		str := "failed to create block output bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketImmaturedCoinbaseOutput); err != nil {
		str := "failed to create immature coinbase txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketImmaturedOutput); err != nil {
		str := "failed to create immature txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketMaturedOutput); err != nil {
		str := "failed to create mature txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketSpentButUnmined); err != nil {
		str := "failed to create unspent but unmined txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketSpentConfirmed); err != nil {
		str := "failed to create spent and confirmed bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketUTXORing); err != nil {
		str := "failed to create utxo ring bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketRingDetails); err != nil {
		str := "failed to create ring details bucket"
		return storeError(ErrDatabase, str, err)
	}

	if _, err := ns.CreateBucket(bucketUnconfirmedTx); err != nil {
		str := "failed to create unconfirmed transaction bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketInvalidTx); err != nil {
		str := "failed to create invalid transaction bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketConfirmedTx); err != nil {
		str := "failed to create confirmed transaction bucket"
		return storeError(ErrDatabase, str, err)
	}

	if _, err := ns.CreateBucket(bucketRelevantTxs); err != nil {
		str := "failed to create relevant transactions bucket"
		return storeError(ErrDatabase, str, err)
	}

	if _, err := ns.CreateBucket(bucketAUTPoint); err != nil {
		str := "failed to create aut point bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketBlockDisabledAUTPoint); err != nil {
		str := "failed to create block disbaled aut point bucket"
		return storeError(ErrDatabase, str, err)
	}

	if _, err := ns.CreateBucket(bucketCTAUTPoint); err != nil {
		str := "failed to create aut point bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketBlockDisabledCTAUTPoint); err != nil {
		str := "failed to create block disbaled aut point bucket"
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// deleteBuckets deletes all of the descendants buckets required for the
// transaction store to properly carry its duties.
func deleteBuckets(ns walletdb.ReadWriteBucket) error {
	if err := ns.DeleteNestedBucket(bucketLockedOutputs); err != nil {
		str := "failed to delete locked outputs bucket"
		return storeError(ErrDatabase, str, err)
	}
	//TODO(abe):change the name of bucket
	if err := ns.DeleteNestedBucket(bucketBlocks); err != nil {
		str := "failed to delete block bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketBlockInputs); err != nil {
		str := "failed to delete block input bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketBlockOutputs); err != nil {
		str := "failed to delete block output bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketImmaturedCoinbaseOutput); err != nil {
		str := "failed to delete immature coinbase txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketImmaturedOutput); err != nil {
		str := "failed to delete immature txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketMaturedOutput); err != nil {
		str := "failed to delete mature txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketSpentButUnmined); err != nil {
		str := "failed to delete spent but unmined txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketSpentConfirmed); err != nil {
		str := "failed to delete spent and confirmed txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketUTXORing); err != nil {
		str := "failed to delete utxo ring bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketRingDetails); err != nil {
		str := "failed to delete utxo details bucket"
		return storeError(ErrDatabase, str, err)
	}

	if err := ns.DeleteNestedBucket(bucketUnconfirmedTx); err != nil {
		str := "failed to delete unconfirmed transaction bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketInvalidTx); err != nil {
		str := "failed to delete invalid transaction bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketConfirmedTx); err != nil {
		str := "failed to delete confirmed transaction bucket"
		return storeError(ErrDatabase, str, err)
	}

	if err := ns.DeleteNestedBucket(bucketRelevantTxs); err != nil {
		str := "failed to delete relevant transactions bucket"
		return storeError(ErrDatabase, str, err)
	}

	if err := ns.DeleteNestedBucket(bucketAUTPoint); err != nil {
		str := "failed to delete aut point bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketBlockDisabledAUTPoint); err != nil {
		str := "failed to delete block disabled aut point bucket"
		return storeError(ErrDatabase, str, err)
	}

	if err := ns.DeleteNestedBucket(bucketCTAUTPoint); err != nil {
		str := "failed to delete aut point bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketBlockDisabledCTAUTPoint); err != nil {
		str := "failed to delete block disabled aut point bucket"
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// putVersion modifies the version of the store to reflect the given version
// number.
func putVersion(ns walletdb.ReadWriteBucket, version uint32) error {
	var v [4]byte
	byteOrder.PutUint32(v[:], version)
	if err := ns.Put(rootVersion, v[:]); err != nil {
		str := "failed to store database version"
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// fetchVersion fetches the current version of the store.
func fetchVersion(ns walletdb.ReadBucket) (uint32, error) {
	v := ns.Get(rootVersion)
	if len(v) != 4 {
		str := "no transaction store exists in namespace"
		return 0, storeError(ErrNoExists, str, nil)
	}

	return byteOrder.Uint32(v), nil
}
