package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewalletmlp/waddrmgr"
	"github.com/abesuite/abewalletmlp/walletdb"
	"github.com/lightningnetwork/lnd/clock"
)

const (
	// TxLabelLimit is the length limit we impose on transaction labels.
	TxLabelLimit = 500

	// DefaultLockDuration is the default duration used to lock outputs.
	DefaultLockDuration = 10 * time.Minute
)

var (
	// ErrEmptyLabel is returned when an attempt to write a label that is
	// empty is made.
	ErrEmptyLabel = errors.New("empty transaction label not allowed")

	// ErrLabelTooLong is returned when an attempt to write a label that is
	// to long is made.
	ErrLabelTooLong = errors.New("transaction label exceeds limit")

	// ErrNoLabelBucket is returned when the bucket holding optional
	// transaction labels is not found. This occurs when no transactions
	// have been labelled yet.
	ErrNoLabelBucket = errors.New("labels bucket does not exist")

	// ErrTxLabelNotFound is returned when no label is found for a
	// transaction hash.
	ErrTxLabelNotFound = errors.New("label for transaction not found")

	// ErrUnknownOutput is an error returned when an output not known to the
	// wallet is attempted to be locked.
	ErrUnknownOutput = errors.New("unknown output")

	// ErrOutputAlreadyLocked is an error returned when an output has
	// already been locked to a different ID.
	ErrOutputAlreadyLocked = errors.New("output already locked")

	// ErrOutputUnlockNotAllowed is an error returned when an output unlock
	// is attempted with a different ID than the one which locked it.
	ErrOutputUnlockNotAllowed = errors.New("output unlock not alowed")
)

// Block contains the minimum amount of data to uniquely identify any block on
// either the best or side chain.
type Block struct {
	Hash   chainhash.Hash
	Height int32
}

// BlockMeta contains the unique identification for a block and any metadata
// pertaining to the block.  At the moment, this additional metadata only
// includes the block time from the block header.
type BlockMeta struct {
	Block
	Time time.Time
}

type BlockRecord struct {
	MsgBlock        wire.MsgBlockAbe //TODO(abe):using a pointer replace the struct
	Height          int32
	Hash            chainhash.Hash
	RecvTime        time.Time
	TxRecords       []*TxRecord
	SerializedBlock []byte
}

func NewBlockRecord(serializedBlock []byte) (*BlockRecord, error) {
	rec := &BlockRecord{
		SerializedBlock: serializedBlock,
	}
	err := rec.MsgBlock.DeserializeNoWitness(bytes.NewReader(serializedBlock))
	if err != nil {
		str := "failed to deserialize block"
		return nil, storeError(ErrInput, str, err)
	}
	blockHash := rec.MsgBlock.BlockHash()
	copy(rec.Hash[:], blockHash.CloneBytes())
	rec.Height = int32(binary.BigEndian.Uint32(rec.MsgBlock.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[0][0:4]))
	rec.RecvTime = rec.MsgBlock.Header.Timestamp
	rec.TxRecords = make([]*TxRecord, len(rec.MsgBlock.Transactions))
	for i := 0; i < len(rec.MsgBlock.Transactions); i++ {
		rec.TxRecords[i], err = NewTxRecordFromMsgTx(rec.MsgBlock.Transactions[i], rec.RecvTime)
		if err != nil {
			return nil, err
		}
	}
	return rec, nil

}
func NewBlockRecordFromMsgBlock(msgBlock *wire.MsgBlockAbe) (*BlockRecord, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgBlock.SerializeSize()))
	err := msgBlock.Serialize(buf)
	if err != nil {
		str := "failed to serialize block"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &BlockRecord{
		MsgBlock:        *msgBlock,
		Height:          int32(binary.BigEndian.Uint32(msgBlock.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[0][0:4])),
		Hash:            msgBlock.BlockHash(),
		RecvTime:        msgBlock.Header.Timestamp,
		TxRecords:       make([]*TxRecord, len(msgBlock.Transactions)),
		SerializedBlock: buf.Bytes(),
	}
	for i := 0; i < len(msgBlock.Transactions); i++ {
		rec.TxRecords[i], err = NewTxRecordFromMsgTx(rec.MsgBlock.Transactions[i], rec.RecvTime)
		if err != nil {
			return nil, err
		}
	}
	return rec, nil
}

// blockRecord is an in-memory representation of the block record saved in the
// database.
type blockRecord struct {
	Block
	Time         time.Time
	transactions []chainhash.Hash
}

// incidence records the block hash and blockchain height of a mined transaction.
// Since a transaction hash alone is not enough to uniquely identify a mined
// transaction (duplicate transaction hashes are allowed), the incidence is used
// instead.
type incidence struct {
	txHash chainhash.Hash
	block  Block
}

// indexedIncidence records the transaction incidence and an input or output
// index.
type indexedIncidence struct {
	incidence
	index uint32
}

// debit records the debits a transaction record makes from previous wallet
// transaction credits.

// credit describes a transaction output which was or is spendable by wallet.

// TxRecord represents a transaction managed by the Store.
// TODO: this struct would be add more information for managing transaction
type TxRecord struct {
	MsgTx        wire.MsgTxAbe
	Hash         chainhash.Hash
	Received     time.Time // record the record status
	SerializedTx []byte    // Optional: may be nil
}

func (tx *TxRecord) Serialize() ([]byte, error) {
	var v []byte
	if len(tx.SerializedTx) == 0 {
		var w bytes.Buffer
		err := tx.MsgTx.Serialize(&w)
		if err != nil {
			return nil, fmt.Errorf("unable to serialize transaction %s:%v", tx.Hash, err)
		}
		tx.SerializedTx = w.Bytes()
	}

	v = make([]byte, 8+len(tx.SerializedTx))
	byteOrder.PutUint64(v[:8], uint64(tx.Received.Unix()))
	copy(v[8:8+len(tx.SerializedTx)], tx.SerializedTx)

	return v, nil
}

func (tx *TxRecord) Deserialize(v []byte) error {
	if len(v) < 8 {
		return errors.New("invalid serialized transaction")
	}
	tx.Received = time.Unix(int64(byteOrder.Uint64(v[:8])), 0)
	tx.SerializedTx = v[8:]
	err := tx.MsgTx.Deserialize(bytes.NewReader(tx.SerializedTx))
	if err != nil {
		return err
	}

	tx.Hash = tx.MsgTx.TxHash()
	return nil
}

// NewTxRecord creates a new transaction record that may be inserted into the
// store.  It uses memoization to save the transaction hash and the serialized
// transaction.
func NewTxRecord(serializedTx []byte, received time.Time) (*TxRecord, error) {
	rec := &TxRecord{
		Received:     received,
		SerializedTx: serializedTx,
	}
	err := rec.MsgTx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		str := "failed to deserialize transaction"
		return nil, storeError(ErrInput, str, err)
	}

	// todo: Investigate the use of DoubleHashB/DoubleHashH (to SHA3-256) in Aconcagua upgrade
	copy(rec.Hash[:], chainhash.DoubleHashB(serializedTx))
	return rec, nil
}

// NewTxRecordFromMsgTx creates a new transaction record that may be inserted
// into the store.
func NewTxRecordFromMsgTx(msgTx *wire.MsgTxAbe, received time.Time) (*TxRecord, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSizeFull()))
	err := msgTx.SerializeFull(buf)
	if err != nil {
		str := "failed to serialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &TxRecord{
		MsgTx:        *msgTx,
		Received:     received,
		SerializedTx: buf.Bytes(),
		Hash:         msgTx.TxHash(),
	}

	return rec, nil
}

type AUTCoin struct {
	TxOutput      wire.OutPointAbe
	AUTIdentifier []byte
	IsAUTRootCoin bool
	AUTCoinValue  uint64
	AddrKey       []byte
	Spent         bool
}
type CTAUTCoin struct {
	TxOutput        wire.OutPointAbe
	Height          int32
	AUTIdentifier   []byte
	IsAUTRootCoin   bool
	AutTxoType      abecryptox.AutTxoType
	CoinValueScript []byte
	Value           uint64
	AddrKey         []byte
	PublicRand      []byte
	Spent           bool
}

func NewAUTCoin(outpoint wire.OutPointAbe, autIdentifier []byte, isAUTRootCoin bool, autCoinValue uint64, addrKey []byte) *AUTCoin {
	return &AUTCoin{
		TxOutput:      outpoint,
		AUTIdentifier: autIdentifier,
		IsAUTRootCoin: isAUTRootCoin,
		AUTCoinValue:  autCoinValue,
		AddrKey:       addrKey,
	}
}
func NewCTAUTCoin(outpoint wire.OutPointAbe, height int32,
	autIdentifier []byte,
	isAUTRootCoin bool, autTxoType abecryptox.AutTxoType,
	ctAUTCoinValueScript []byte, value uint64,
	addrKey []byte, publicRand []byte) *CTAUTCoin {
	return &CTAUTCoin{
		TxOutput:        outpoint,
		Height:          height,
		AUTIdentifier:   autIdentifier,
		IsAUTRootCoin:   isAUTRootCoin,
		AutTxoType:      autTxoType,
		CoinValueScript: ctAUTCoinValueScript,
		Value:           value,
		AddrKey:         addrKey,
		PublicRand:      publicRand,
		Spent:           false,
	}
}

func (coin *AUTCoin) Serialized() ([]byte, error) {
	res := make([]byte, chainhash.HashSize+1+4+len(coin.AUTIdentifier)+1+8+4+len(coin.AddrKey)+1)

	offset := 0
	copy(res[offset:], coin.TxOutput.TxHash[:])
	offset += chainhash.HashSize
	res[offset] = coin.TxOutput.Index
	offset += 1

	byteOrder.PutUint32(res[offset:], uint32(len(coin.AUTIdentifier)))
	offset += 4
	copy(res[offset:], coin.AUTIdentifier)
	offset += len(coin.AUTIdentifier)

	//_ = coin.IsAUTRootCoin //  byte 1
	if coin.IsAUTRootCoin {
		res[offset] = 1
	} else {
		res[offset] = 0
	}
	offset += 1

	//_ = coin.AUTCoinValue  //   8
	byteOrder.PutUint64(res[offset:], coin.AUTCoinValue)
	offset += 8

	byteOrder.PutUint32(res[offset:], uint32(len(coin.AddrKey)))
	offset += 4
	copy(res[offset:], coin.AddrKey)
	offset += len(coin.AddrKey)

	//_ = coin.Spent         //   byte 1
	if coin.Spent {
		res[offset] = 1
	} else {
		res[offset] = 0
	}
	offset += 1

	return res, nil
}
func (coin *CTAUTCoin) Serialized() ([]byte, error) {
	res := make([]byte, chainhash.HashSize+1+8+
		4+len(coin.AUTIdentifier)+
		1+
		8+len(coin.CoinValueScript)+8+
		4+len(coin.AddrKey)+
		4+len(coin.PublicRand)+
		1,
	)

	offset := 0
	copy(res[offset:], coin.TxOutput.TxHash[:])
	offset += chainhash.HashSize
	res[offset] = coin.TxOutput.Index
	offset += 1
	byteOrder.PutUint32(res[offset:], uint32(coin.Height))
	offset += 4

	byteOrder.PutUint32(res[offset:], uint32(len(coin.AUTIdentifier)))
	offset += 4
	copy(res[offset:], coin.AUTIdentifier)
	offset += len(coin.AUTIdentifier)

	// 000000 | coin.coin.AutTxoType | coin.IsAUTRootCoin
	if coin.IsAUTRootCoin {
		res[offset] = 1 << 0
	} else {
		res[offset] = 0 << 0
	}
	res[offset] |= uint8(coin.AutTxoType) << 1
	offset += 1

	byteOrder.PutUint64(res[offset:], uint64(len(coin.CoinValueScript)))
	offset += 8
	copy(res[offset:], coin.CoinValueScript)
	offset += len(coin.CoinValueScript)

	//_ = coin.AUTCoinValue  //   8
	byteOrder.PutUint64(res[offset:], coin.Value)
	offset += 8

	byteOrder.PutUint32(res[offset:], uint32(len(coin.AddrKey)))
	offset += 4
	copy(res[offset:], coin.AddrKey)
	offset += len(coin.AddrKey)

	byteOrder.PutUint32(res[offset:], uint32(len(coin.PublicRand)))
	offset += 4
	copy(res[offset:], coin.PublicRand)
	offset += len(coin.PublicRand)

	//_ = coin.Spent         //   byte 1
	if coin.Spent {
		res[offset] = 1
	} else {
		res[offset] = 0
	}
	offset += 1

	return res, nil
}
func (utxo *AUTCoin) Deserialize(op *wire.OutPointAbe, v []byte) error {
	if v == nil {
		return fmt.Errorf("empty byte slice")
	}
	//	if len(v) < 49 { // todo: 2021.06.16 hardcode needs to be fixed
	if len(v) < 55 { // todo: 2021.06.16 hardcode needs to be fixed
		str := "wrong size of serialized unspent transaction output"
		return fmt.Errorf(str)
	}
	utxo.TxOutput.TxHash = op.TxHash
	utxo.TxOutput.Index = op.Index

	offset := 0
	txHash, _ := chainhash.NewHash(v[offset : offset+chainhash.HashSize])
	offset += chainhash.HashSize
	if !op.TxHash.IsEqual(txHash) {
		str := "unmatched aut coin with outpoint"
		return fmt.Errorf(str)
	}
	index := v[offset]
	offset += 1
	if index != op.Index {
		str := "unmatched aut coin with outpoint"
		return fmt.Errorf(str)
	}

	autIdentifierSize := int(byteOrder.Uint32(v[offset:]))
	offset += 4
	utxo.AUTIdentifier = v[offset : offset+autIdentifierSize]
	offset += autIdentifierSize

	t := v[offset]
	offset += 1
	if t == 0 {
		utxo.IsAUTRootCoin = false
	} else {
		utxo.IsAUTRootCoin = true
	}

	utxo.AUTCoinValue = byteOrder.Uint64(v[offset : offset+8])
	offset += 8

	addrKeySize := int(byteOrder.Uint32(v[offset:]))
	offset += 4
	utxo.AddrKey = v[offset : offset+addrKeySize]
	offset += addrKeySize

	t = v[offset]
	offset += 1
	if t == 0 {
		utxo.Spent = false
	} else {
		utxo.Spent = true
	}
	return nil
}
func (utxo *CTAUTCoin) Deserialize(op *wire.OutPointAbe, v []byte) error {
	if v == nil {
		return fmt.Errorf("empty byte slice")
	}
	//	if len(v) < 49 { // todo: 2021.06.16 hardcode needs to be fixed
	if len(v) < 55 { // todo: 2021.06.16 hardcode needs to be fixed
		str := "wrong size of serialized ct-aut token"
		return fmt.Errorf(str)
	}
	utxo.TxOutput.TxHash = op.TxHash
	utxo.TxOutput.Index = op.Index

	offset := 0
	txHash, _ := chainhash.NewHash(v[offset : offset+chainhash.HashSize])
	offset += chainhash.HashSize
	if !op.TxHash.IsEqual(txHash) {
		str := "unmatched aut coin with outpoint"
		return fmt.Errorf(str)
	}
	index := v[offset]
	offset += 1
	if index != op.Index {
		str := "unmatched aut coin with outpoint"
		return fmt.Errorf(str)
	}
	utxo.Height = int32(byteOrder.Uint32(v[offset:]))
	offset += 4

	autIdentifierSize := int(byteOrder.Uint32(v[offset:]))
	offset += 4
	utxo.AUTIdentifier = v[offset : offset+autIdentifierSize]
	offset += autIdentifierSize

	t := v[offset]
	offset += 1
	if t&0x01 == 0 {
		utxo.IsAUTRootCoin = false
	} else {
		utxo.IsAUTRootCoin = true
	}
	utxo.AutTxoType = abecryptox.AutTxoType((t & 0x02) >> 1)

	coinValueScriptSize := int(byteOrder.Uint64(v[offset:]))
	offset += 8
	utxo.CoinValueScript = v[offset : offset+coinValueScriptSize]
	offset += coinValueScriptSize

	utxo.Value = byteOrder.Uint64(v[offset : offset+8])
	offset += 8

	addrKeySize := int(byteOrder.Uint32(v[offset:]))
	offset += 4
	utxo.AddrKey = v[offset : offset+addrKeySize]
	offset += addrKeySize

	publicRandSize := int(byteOrder.Uint32(v[offset:]))
	offset += 4
	utxo.PublicRand = v[offset : offset+publicRandSize]
	offset += publicRandSize

	t = v[offset]
	offset += 1
	if t == 0 {
		utxo.Spent = false
	} else {
		utxo.Spent = true
	}
	return nil
}

// Credit is the type representing a transaction output which was spent or
// is still spendable by wallet.  A UTXO is an unspent Credit, but not all
// Credits are UTXOs.

// txoFlag contains additional info about output such as
// - whether it is a coinbase coin,
// - whether it is a full-privacy coin or pseudonymous coin,
// - whether it is coin for some application
// since it was loaded.  This approach is used in order to reduce memory
// usage since there will be a lot of these in memory.
type txoFlag uint8

const (
	txoFlagCoinbase       txoFlag = 1 << 0
	txoFlagAUTCoin        txoFlag = 1 << 1
	txoFlagPseudonymous   txoFlag = 1 << 2
	txoFlagCTAUTCoin      txoFlag = 1 << 3
	txoFlagPseudonymousCT txoFlag = 1 << 4
)

type SpendableTXO struct {
	Version        uint32           // todo: added by AliceBob 20210616, the version of corresponding Txo in blockchain, and the same as that of the ring
	Height         int32            // the block height used to identify whether this utox can be spent in current height
	TxOutput       wire.OutPointAbe //the outpoint
	PackedFlag     txoFlag
	Amount         uint64
	PublicRand     []byte
	GenerationTime time.Time      //at this moment, it also useless
	RingHash       chainhash.Hash //may be zero
	RingSize       uint8          // set together with RingHash, uint8 is reasonable and larger enough
	RingIndex      uint8          //indicate the index in the ring, if not in a ring, it equals to -1 TODO_DONE(osy,20210617) finish this field read and write
	UTXOHash       chainhash.Hash
}

func NewUnspentUTXO(
	version uint32, height int32, txOutput wire.OutPointAbe,
	fromCoinBase bool,
	amount uint64, ringIndex uint8,
	generationTime time.Time,
	ringHash chainhash.Hash, ringSize uint8,
	privacyLevel abecryptoxkey.PrivacyLevel, publicRand []byte,
) *SpendableTXO {
	packedFlag := txoFlag(0)
	if fromCoinBase {
		packedFlag |= txoFlagCoinbase
	}
	if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
		packedFlag |= txoFlagPseudonymous

	} else if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		packedFlag |= txoFlagPseudonymousCT
	}
	return &SpendableTXO{
		Version: version, Height: height, TxOutput: txOutput,
		PackedFlag: packedFlag, Amount: amount, RingIndex: ringIndex,
		GenerationTime: generationTime, PublicRand: publicRand, RingHash: ringHash, RingSize: ringSize}
}
func (txo *SpendableTXO) IsCoinbase() bool {
	return txo.PackedFlag&txoFlagCoinbase == txoFlagCoinbase
}
func (txo *SpendableTXO) IsPseudonymous() bool {
	return txo.PackedFlag&txoFlagPseudonymous == txoFlagPseudonymous
}
func (txo *SpendableTXO) IsAUTCoin() bool {
	return txo.PackedFlag&txoFlagAUTCoin == txoFlagAUTCoin
}
func (txo *SpendableTXO) IsPseudonymousCT() bool {
	return txo.PackedFlag&txoFlagPseudonymousCT == txoFlagPseudonymousCT
}
func (txo *SpendableTXO) IsCTAUTCoin() bool {
	return txo.PackedFlag&txoFlagCTAUTCoin == txoFlagCTAUTCoin
}
func (txo *SpendableTXO) Hash() chainhash.Hash {
	if !txo.UTXOHash.IsEqual(&chainhash.ZeroHash) {
		return txo.UTXOHash
	}

	// Version + Height + TxOutput.TxHash + TxOutput.Index + Amount + RingHash + RingSize + RingIndex
	// 4 + 4 + 32 + 1 + 8 + 32 + 1 + 1
	buf := make([]byte, 4+4+chainhash.HashSize+1+8+chainhash.HashSize+1+1)
	offset := 0
	// 4   Version uint32
	byteOrder.PutUint32(buf[offset:offset+4], txo.Version)
	offset += 4
	// 4   Height  int32
	byteOrder.PutUint32(buf[offset:offset+4], uint32(txo.Height))
	offset += 4
	// TxOutput.TxHash
	copy(buf[offset:offset+chainhash.HashSize], txo.TxOutput.TxHash[:])
	offset += chainhash.HashSize
	//  TxOutput.Index
	buf[offset] = txo.TxOutput.Index
	offset += 1
	// 8   Amount     uint64
	byteOrder.PutUint64(buf[offset:offset+8], txo.Amount)
	offset += 8
	// 32  RingHash   chainhash.Hash
	copy(buf[offset:offset+chainhash.HashSize], txo.RingHash[:])
	offset += chainhash.HashSize
	// 1   RingSize    uint8
	buf[offset] = txo.RingSize
	offset += 1
	// 1   RingIndex   uint8
	buf[offset] = txo.RingIndex
	offset += 1

	// todo: Investigate the use of DoubleHashB/DoubleHashH (to SHA3-256) in Aconcagua upgrade
	txo.UTXOHash = chainhash.DoubleHashH(buf)
	return txo.UTXOHash
}

const PublicRandBytesLen = 64
const SpendableTXOSerializedSize = 4 + 4 + 1 + 8 + PublicRandBytesLen + chainhash.HashSize + 1 + 1 + chainhash.HashSize + +8

func (txo *SpendableTXO) Serialize() ([]byte, error) {
	size := SpendableTXOSerializedSize
	v := make([]byte, size)
	offset := 0
	// 4   Version uint32
	byteOrder.PutUint32(v[offset:offset+4], txo.Version)
	offset += 4
	// 4   Height  int32
	byteOrder.PutUint32(v[offset:offset+4], uint32(txo.Height))
	offset += 4
	// 0   TxOutput   wire.OutPointAbe As key
	// 1   PackedFlag txoFlag
	v[offset] = byte(txo.PackedFlag)
	offset += 1
	// 8   Amount     uint64
	byteOrder.PutUint64(v[offset:offset+8], txo.Amount)
	offset += 8

	// 64  PublicRand   []byte
	copy(v[offset:offset+PublicRandBytesLen], txo.PublicRand[:])
	offset += PublicRandBytesLen

	// 32  RingHash   chainhash.Hash
	copy(v[offset:offset+chainhash.HashSize], txo.RingHash[:])
	offset += chainhash.HashSize
	// 1   RingSize    uint8
	v[offset] = txo.RingSize
	offset += 1
	// 1   RingIndex   uint8
	v[offset] = txo.RingIndex
	offset += 1

	// 32  UTXOHash    chainhash.Hash
	utxoHash := txo.Hash()
	copy(v[offset:offset+chainhash.HashSize], utxoHash[:])
	offset += chainhash.HashSize

	// 8   GenerationTime time.Time
	byteOrder.PutUint64(v[offset:offset+8], uint64(txo.GenerationTime.Unix()))
	offset += 8

	return v, nil
}
func (txo *SpendableTXO) Deserialize(op *wire.OutPointAbe, v []byte) error {
	if v == nil {
		return fmt.Errorf("empty byte slice")
	}
	//	if len(v) < 49 { // todo: 2021.06.16 hardcode needs to be fixed
	if len(v) < SpendableTXOSerializedSize { // todo: 2021.06.16 hardcode needs to be fixed
		str := "wrong size of serialized unspent transaction output"
		return fmt.Errorf(str)
	}
	txo.TxOutput.TxHash = op.TxHash
	txo.TxOutput.Index = op.Index
	offset := 0
	txo.Version = byteOrder.Uint32(v[offset : offset+4])
	offset += 4
	txo.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
	offset += 4
	txo.PackedFlag = txoFlag(v[offset])
	offset += 1
	txo.Amount = byteOrder.Uint64(v[offset : offset+8])
	offset += 8
	// 64  PublicRand   []byte
	txo.PublicRand = make([]byte, PublicRandBytesLen)
	copy(txo.PublicRand[:], v[offset:offset+PublicRandBytesLen])
	offset += PublicRandBytesLen

	copy(txo.RingHash[:], v[offset:offset+chainhash.HashSize])
	offset += chainhash.HashSize
	txo.RingSize = uint8(v[offset])
	offset += 1
	txo.RingIndex = v[offset]
	offset += 1

	copy(txo.UTXOHash[:], v[offset:offset+chainhash.HashSize])
	offset += chainhash.HashSize

	txo.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8

	return nil
}

type UnconfirmedTXO struct { //TODO(abe):should add a field to denote which tx spent this utxo
	SpendableTXO
	SpentByHash chainhash.Hash
	SpentTime   time.Time
}

func (txo *UnconfirmedTXO) Hash() chainhash.Hash {
	return txo.SpendableTXO.Hash()
}

const UnconfirmedTXOSerializedSize = SpendableTXOSerializedSize + chainhash.HashSize + 8

func (txo *UnconfirmedTXO) Serialize() ([]byte, error) {
	serializeUTXO, err := txo.SpendableTXO.Serialize()
	if err != nil {
		return nil, err
	}

	res := make([]byte, UnconfirmedTXOSerializedSize)
	offset := 0

	copy(res[offset:offset+len(serializeUTXO)], serializeUTXO[:])
	offset += len(serializeUTXO)

	copy(res[offset:offset+chainhash.HashSize], txo.SpentByHash[:])
	offset += chainhash.HashSize

	byteOrder.PutUint64(res[offset:offset+8], uint64(txo.SpentTime.Unix()))
	offset += 8

	return res, nil
}
func (txo *UnconfirmedTXO) Deserialize(op *wire.OutPointAbe, v []byte) error {
	if v == nil {
		return fmt.Errorf("empty byte slice")
	}
	if len(v) < UnconfirmedTXOSerializedSize { // todo: 2021.06.16 hardcode needs to be fixed
		str := "wrong size of serialized spend but unmined transaction output"
		return fmt.Errorf(str)
	}

	err := txo.SpendableTXO.Deserialize(op, v)
	if err != nil {
		return err
	}
	offset := SpendableTXOSerializedSize

	copy(txo.SpentByHash[:], v[offset:offset+chainhash.HashSize])
	offset += chainhash.HashSize

	txo.SpentTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8

	return nil
}

type ConfirmedTXO struct { //TODO(abe):should add a field to denote which tx spent this utxo
	UnconfirmedTXO
	ConfirmedByBlockHash chainhash.Hash
	ConfirmTime          time.Time
}

func (txo *ConfirmedTXO) Hash() chainhash.Hash {
	return txo.SpendableTXO.Hash()
}

const ConfirmedTXOSerializedSize = UnconfirmedTXOSerializedSize + chainhash.HashSize + 8

func (txo *ConfirmedTXO) Serialize() ([]byte, error) {
	serializeUnconfirmedUTXO, err := txo.UnconfirmedTXO.Serialize()
	if err != nil {
		return nil, err
	}

	res := make([]byte, ConfirmedTXOSerializedSize)
	offset := 0

	copy(res[offset:offset+UnconfirmedTXOSerializedSize], serializeUnconfirmedUTXO[:])
	offset += UnconfirmedTXOSerializedSize

	copy(res[offset:offset+chainhash.HashSize], txo.ConfirmedByBlockHash[:])
	offset += chainhash.HashSize

	byteOrder.PutUint64(res[offset:offset+8], uint64(txo.ConfirmTime.Unix()))
	offset += 8

	return res, nil
}
func (txo *ConfirmedTXO) Deserialize(op *wire.OutPointAbe, v []byte) error {
	if v == nil {
		return fmt.Errorf("empty byte slice")
	}
	if len(v) < ConfirmedTXOSerializedSize {
		str := "wrong size of serialized unspent transaction output"
		return fmt.Errorf(str)
	}

	err := txo.UnconfirmedTXO.Deserialize(op, v)
	if err != nil {
		return err
	}
	offset := UnconfirmedTXOSerializedSize
	copy(txo.ConfirmedByBlockHash[:], v[offset:offset+chainhash.HashSize])
	offset += chainhash.HashSize

	txo.ConfirmTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8

	return nil
}

// ringFlag contains additional info about output such as
// - whether it is a coinbase coin,
// - whether it is a full-privacy coin or pseudonymous coin,
// - whether it is coin for some application
// since it was loaded.  This approach is used in order to reduce memory
// usage since there will be a lot of these in memory.
type ringFlag uint8

const (
	ringFlagCoinbase     ringFlag = 1 << 0
	ringFlagPseudonymous ringFlag = 1 << 2
)

// TODO(osy)20210608 change the serialize and deserialize
type Ring struct {
	Version     uint32
	BlockHashes []chainhash.Hash // three block hashes
	TxHashes    []chainhash.Hash // [2,8]
	Index       []uint8          // [2,8]
	PackedFlag  ringFlag
	//ValueScript []int64          // [2,8]
	//AddrScript  [][]byte         // [2.8]
	TxoScripts  [][]byte
	BlockHeight int32 // point  height where the utxo ring is deleted
}

// TODO(abe):change the method of serialization, use offset represent the location of corresonpding addr script size
// Serialize serialize the ring struct as such :
// [block hash...]||transaction number||[transaction hash||output index||addrScript Size...]||[addr script...]||hegiht
func (r *Ring) Serialize() []byte {
	addrScriptAllSize := 0 //address script size
	bLen := len(r.BlockHashes)
	txLen := len(r.TxHashes) //transaction number
	txoSize := make([]int, 0, txLen)
	for i := 0; i < txLen; i++ {
		txoSize = append(txoSize, len(r.TxoScripts[i]))
		addrScriptAllSize += len(r.TxoScripts[i])
	}

	total := 4 + chainhash.HashSize*bLen + 2 + (chainhash.HashSize+1+4)*txLen + 1 + addrScriptAllSize + 4
	res := make([]byte, total)
	offset := 0
	byteOrder.PutUint32(res, r.Version)
	offset += 4
	for i := 0; i < bLen; i++ {
		copy(res[offset:offset+chainhash.HashSize], r.BlockHashes[i][:])
		offset += chainhash.HashSize
	}
	byteOrder.PutUint16(res[offset:offset+2], uint16(txLen))
	offset += 2
	for i := 0; i < txLen; i++ {
		copy(res[offset:offset+chainhash.HashSize], r.TxHashes[i][:])
		offset += chainhash.HashSize
		res[offset] = r.Index[i]
		offset += 1
		//byteOrder.PutUint64(res[offset:offset+8], uint64(r.ValueScript[i]))
		//offset += 8
		byteOrder.PutUint32(res[offset:offset+4], uint32(txoSize[i]))
		offset += 4
	}

	res[offset] = byte(r.PackedFlag)
	offset += 1

	for i := 0; i < txLen; i++ {
		copy(res[offset:offset+txoSize[i]], r.TxoScripts[i])
		offset += txoSize[i]
	}
	byteOrder.PutUint32(res[offset:offset+4], uint32(r.BlockHeight))
	offset += 4
	return res
}
func (r *Ring) Deserialize(b []byte) error {
	//	todo: AliceBob 20210616, Version is not handled
	// TODO:20210620 change the checking
	if len(b) < chainhash.HashSize*wire.BlockNumPerRingGroup+(chainhash.HashSize+2+8) {
		return fmt.Errorf("wrong length of input byte slice")
	}
	offset := 0
	r.Version = byteOrder.Uint32(b)
	offset += 4
	for i := 0; i < wire.BlockNumPerRingGroup; i++ {
		newHash, err := chainhash.NewHash(b[offset : offset+chainhash.HashSize])
		if err != nil {
			return err
		}
		r.BlockHashes = append(r.BlockHashes, *newHash)
		offset += chainhash.HashSize
	}
	txLen := int(byteOrder.Uint16(b[offset : offset+2]))
	offset += 2
	addrSize := make([]int, 0, txLen)
	for i := 0; i < txLen; i++ {
		newHash, err := chainhash.NewHash(b[offset : offset+chainhash.HashSize])
		if err != nil {
			return err
		}
		r.TxHashes = append(r.TxHashes, *newHash)
		offset += chainhash.HashSize
		r.Index = append(r.Index, b[offset])
		offset += 1
		//r.ValueScript = append(r.ValueScript, int64(byteOrder.Uint64(b[offset:offset+8])))
		//offset += 8
		addrSize = append(addrSize, int(byteOrder.Uint32(b[offset:offset+4])))
		offset += 4
	}

	r.PackedFlag = ringFlag(b[offset])
	offset += 1

	r.TxoScripts = make([][]byte, txLen)
	for i := 0; i < txLen; i++ {
		r.TxoScripts[i] = b[offset : offset+addrSize[i]]
		offset += addrSize[i]
	}
	r.BlockHeight = int32(byteOrder.Uint32(b[offset : offset+4]))
	offset += 4
	return nil
}

// blockHash0||blockHash1||blockHash2||txHash0||index0||txHash1||index1||...
func (r Ring) Hash() []byte {
	//	todo: AliceBob 20210616, Version is not handled
	//  todo: what is the relation between the ring here and the utxoring in abec? Shall they be kept consistent?

	//blockNum, err := wire.GetBlockNumPerRingGroupByRingVersion(r.Version)
	//if err != nil {
	//	return nil
	//}
	blockNum := len(r.BlockHashes)
	size := 4 + 1 + blockNum*chainhash.HashSize + 1 + len(r.TxHashes)*(chainhash.HashSize+1)
	v := make([]byte, size)
	offset := 0
	byteOrder.PutUint32(v[offset:offset+4], r.Version)
	offset += 4
	v[offset] = uint8(blockNum)
	offset += 1
	for i := 0; i < blockNum; i++ {
		copy(v[offset:offset+32], r.BlockHashes[i][:])
		offset += 32
	}
	v[offset] = uint8(len(r.TxHashes))
	offset += 1
	for i := 0; i < len(r.TxHashes); i++ {
		copy(v[offset:offset+32], r.TxHashes[i][:])
		offset += 32
		v[offset] = r.Index[i]
		offset += 1
	}

	// todo: Investigate the use of DoubleHashB/DoubleHashH (to SHA3-256) in Aconcagua upgrade
	return chainhash.DoubleHashB(v)
}

type UTXORing struct {
	Version              uint32
	AllSpent             bool             //1 // not serialized and when serializing it must be false, otherwise it will be deleted
	Refreshed            bool             //1 // not serialied, it can be computed from any OriginSerializeNumber
	RingHash             chainhash.Hash   //32
	TxHashes             []chainhash.Hash //32*len
	OutputIndexes        []uint8          //1
	OriginSerialNumberes map[uint8][]byte //variable
	IsMy                 []bool           //total 1
	Spent                []bool           // total 1
	GotSerialNumberes    [][]byte         // variable
	//SpentByTxHashes      []chainhash.Hash
	//InputIndexes         []uint8
	PackedFlag ringFlag
}

func NewUTXORingFromRing(r *Ring, ringHash chainhash.Hash) (*UTXORing, error) {
	ringSize := len(r.TxHashes)
	return &UTXORing{
		Version:              r.Version,
		AllSpent:             false,
		Refreshed:            false,
		RingHash:             ringHash,
		TxHashes:             r.TxHashes,
		OutputIndexes:        r.Index,
		OriginSerialNumberes: make(map[uint8][]byte),
		IsMy:                 make([]bool, ringSize),
		Spent:                make([]bool, ringSize),
		GotSerialNumberes:    [][]byte{},
		PackedFlag:           r.PackedFlag,
	}, nil
}

type RingHashSerialNumbers struct {
	utxoRings     map[chainhash.Hash]UTXORing // utxo ring states before processing the block
	serialNumbers map[chainhash.Hash][][]byte //added serialNumber in given block
}

// ring hash || transaction number || [transaction hash||output index...]||Origin serial number ||[index||serial number...]||isMy||Spent||Got serial number||[serial number...]
func (u UTXORing) SerializeSize() int {
	snSize, _ := abecryptoxparam.GetSerialNumberSerializeSize(u.Version)
	return 4 + 1 + chainhash.HashSize + 1 + len(u.TxHashes)*(chainhash.HashSize+1) + 1 + len(u.OriginSerialNumberes)*(1+snSize) + 2 + 1 + len(u.GotSerialNumberes)*snSize

}
func (u UTXORing) Serialize() []byte {
	txLen := len(u.TxHashes) // TODO(osy): may be lack a tx len in serialized utxo ring
	totalSize := u.SerializeSize()
	res := make([]byte, totalSize)
	offset := 0
	byteOrder.PutUint32(res[offset:offset+4], u.Version)
	offset += 4
	res[offset] = byte(u.PackedFlag)
	offset += 1
	copy(res[offset:offset+chainhash.HashSize], u.RingHash[:])
	offset += chainhash.HashSize
	res[offset] = uint8(txLen)
	offset += 1
	for i := 0; i < txLen; i++ {
		copy(res[offset:offset+chainhash.HashSize], u.TxHashes[i][:])
		offset += chainhash.HashSize
		res[offset] = u.OutputIndexes[i]
		offset += 1
	}
	res[offset] = uint8(len(u.OriginSerialNumberes))
	offset += 1
	snSize, _ := abecryptoxparam.GetSerialNumberSerializeSize(u.Version)
	for index, sn := range u.OriginSerialNumberes {
		res[offset] = index
		offset += 1
		copy(res[offset:offset+snSize], sn[:])
		offset += snSize
	}
	var temp uint16
	for i := 0; i < txLen; i++ {
		if u.IsMy[i] {
			temp |= 1 << i
		}
		if u.Spent[i] {
			temp |= 1 << (i + 8)
		}
	}
	byteOrder.PutUint16(res[offset:offset+2], temp)
	offset += 2
	res[offset] = uint8(len(u.GotSerialNumberes))
	offset += 1
	for i := 0; i < len(u.GotSerialNumberes); i++ {
		copy(res[offset:offset+snSize], u.GotSerialNumberes[i][:])
		offset += snSize
	}
	return res
}
func (u *UTXORing) Deserialize(b []byte) error {
	if len(b) < 32+1 {
		return fmt.Errorf("the length of input byte slice less than minimum size")
	}
	offset := 0
	u.Version = byteOrder.Uint32(b[offset : offset+4])
	offset += 4
	u.PackedFlag = ringFlag(b[offset])
	offset += 1
	copy(u.RingHash[:], b[offset:offset+32])
	offset += 32
	txLen := int(b[offset])
	offset += 1
	u.TxHashes = make([]chainhash.Hash, txLen)
	u.OutputIndexes = make([]uint8, txLen)
	for i := 0; i < txLen; i++ {
		copy(u.TxHashes[i][:], b[offset:offset+32])
		offset += 32
		u.OutputIndexes[i] = b[offset]
		offset += 1
	}
	originSnSize := int(b[offset])
	offset += 1
	snSize, _ := abecryptoxparam.GetSerialNumberSerializeSize(u.Version)
	for i := 0; i < originSnSize; i++ {
		h := make([]byte, snSize)
		copy(h, b[offset+1:offset+1+snSize])
		if u.OriginSerialNumberes == nil {
			u.OriginSerialNumberes = make(map[uint8][]byte)
		}
		u.OriginSerialNumberes[b[offset]] = h[:]
		offset += 1 + snSize
	}
	temp := byteOrder.Uint16(b[offset : offset+2])
	offset += 2
	u.IsMy = make([]bool, txLen)
	u.Spent = make([]bool, txLen)
	for i := 0; i < txLen; i++ {
		if temp&(1<<i) != 0 {
			u.IsMy[i] = true
		}
		if temp&(1<<(i+8)) != 0 {
			u.Spent[i] = true
		}
	}
	gotSnSize := int(b[offset])
	offset += 1
	u.GotSerialNumberes = make([][]byte, gotSnSize)
	for i := 0; i < gotSnSize; i++ {
		u.GotSerialNumberes[i] = make([]byte, snSize)
		copy(u.GotSerialNumberes[i][:], b[offset:offset+snSize])
		offset += snSize
	}
	u.AllSpent = false
	return nil
}

// AddGotSerialNumber The caller must check the u.AllSpent after return
func (u *UTXORing) AddGotSerialNumber(serialNumber []byte) error {
	if u.GotSerialNumberes == nil || len(u.GotSerialNumberes) == 0 {
		u.GotSerialNumberes = make([][]byte, 0)
	}
	for i := 0; i < len(u.GotSerialNumberes); i++ {
		if bytes.Equal(serialNumber, u.GotSerialNumberes[i]) {
			return fmt.Errorf("there has a same serialNumber in UTXORing")
		}
	}

	u.GotSerialNumberes = append(u.GotSerialNumberes, serialNumber)
	// if all serialNumber shown in the chain or all utxo are spent,
	// mark all unspent utxo as spent
	if len(u.GotSerialNumberes) == len(u.TxHashes) {
		for i := 0; i < len(u.IsMy); i++ {
			if u.IsMy[i] && !u.Spent[i] {
				u.Spent[i] = true
			}
		}
		u.AllSpent = true //this utxo will be deleted
		return nil
	}
	// update
	for i := 0; i < len(u.IsMy); i++ {
		if u.IsMy[i] && !u.Spent[i] {
			sn, ok := u.OriginSerialNumberes[uint8(i)]
			if ok && bytes.Equal(sn, serialNumber) {
				u.Spent[i] = true
				break
			}
		}
	}
	// check
	u.AllSpent = true
	for i := 0; i < len(u.IsMy); i++ {
		if u.IsMy[i] && !u.Spent[i] {
			u.AllSpent = false
			break
		}
	}
	return nil
}

func (u UTXORing) Copy() *UTXORing {
	res := new(UTXORing)
	res.Version = u.Version
	res.AllSpent = u.AllSpent
	res.Refreshed = u.Refreshed
	res.RingHash = u.RingHash
	res.TxHashes = make([]chainhash.Hash, len(u.TxHashes))
	for i := 0; i < len(u.TxHashes); i++ {
		res.TxHashes[i] = u.TxHashes[i]
	}
	res.OutputIndexes = make([]uint8, len(u.OutputIndexes))
	for i := 0; i < len(u.OutputIndexes); i++ {
		res.OutputIndexes[i] = u.OutputIndexes[i]
	}
	if res.OriginSerialNumberes == nil {
		res.OriginSerialNumberes = make(map[uint8][]byte)
	}
	for k, v := range u.OriginSerialNumberes {
		res.OriginSerialNumberes[k] = v
	}
	res.IsMy = make([]bool, len(u.IsMy))
	for i := 0; i < len(u.IsMy); i++ {
		res.IsMy[i] = u.IsMy[i]
	}
	res.Spent = make([]bool, len(u.Spent))
	for i := 0; i < len(u.Spent); i++ {
		res.Spent[i] = u.Spent[i]
	}
	res.GotSerialNumberes = make([][]byte, len(u.GotSerialNumberes))
	for i := 0; i < len(u.GotSerialNumberes); i++ {
		res.GotSerialNumberes[i] = u.GotSerialNumberes[i]
	}
	res.PackedFlag = u.PackedFlag
	return res
}

// LockID represents a unique context-specific ID assigned to an output lock.
type LockID [32]byte

// Store implements a transaction store for storing and managing wallet
// transactions.
type Store struct {
	manager *waddrmgr.Manager

	chainParams *chaincfg.Params

	// clock is used to determine when outputs locks have expired.
	clock clock.Clock

	// Event callbacks.  These execute in the same goroutine as the wtxmgr
	// caller.
	NotifyUnspent             func(hash *chainhash.Hash, index uint32)
	NotifyTransactionAccepted func(txInfo *TransactionInfo)
	NotifyTransactionRollback func(txInfo *TransactionInfo)
	NotifyTransactionInvalid  func(txInfo *TransactionInfo)
}
type TransactionInfo struct {
	TxHash *chainhash.Hash
	Height int32
}

// Open opens the wallet transaction store from a walletdb namespace.  If the
// store does not exist, ErrNoExist is returned. `lockDuration` represents how
// long outputs are locked for.
func Open(addrMgr *waddrmgr.Manager, ns walletdb.ReadBucket, chainParams *chaincfg.Params) (*Store, error) {

	// Open the store.
	err := openStore(ns)
	if err != nil {
		return nil, err
	}
	s := &Store{addrMgr, chainParams, clock.NewDefaultClock(), nil, nil, nil, nil} // TODO: set callbacks
	return s, nil
}

// Create creates a new persistent transaction store in the walletdb namespace.
// Creating the store when one already exists in this namespace will error with
// ErrAlreadyExists.
func Create(ns walletdb.ReadWriteBucket) error {
	return createStore(ns)
}

// updateMinedBalance updates the mined balance within the store, if changed,
// after processing the given transaction record.

// deleteUnminedTx deletes an unmined transaction from the store.
//
// NOTE: This should only be used once the transaction has been mined.

// InsertTx records a transaction as belonging to a wallet's transaction
// history.  If block is nil, the transaction is considered unspent, and the
// transaction's index must be unset.
// TODO(abe): actually, we must move the outputs of this transaction from unspent txo bucket to spentButUnmined txo bucket
// TODO(abe): update the balance in this function
// TODO(abe): record this transaction in unmined transaction bucket,
// TODO(abe): wait for a mempool transacion, need to design
func (s *Store) InsertTx(wtxmgrNs walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta) error {
	//TODO(abe):remove the outputs of the wallet spent by given tx from UnspentTXObucket to SpentButUmined bucket
	if block != nil {
		return fmt.Errorf("InsertTx just considerates the unconfirmed transaction")
	}
	v := existsRawUnconfirmedTx(wtxmgrNs, rec.Hash[:])
	if v != nil { // it means that has exists unmined transaction bucket
		return nil
	}
	// move the unspentutxo bucket to spentbutunmined bucket
	for i := 0; i < len(rec.MsgTx.TxIns); i++ {
		// do not update the utxoring bucket  until the transaction packaged into a block
		// just mark it is spent and move from unspent bucket to spentbutunmined bucket
		// to avoid next time spent the same coins
		ringHash := rec.MsgTx.TxIns[i].PreviousOutPointRing.Hash()
		u, err := fetchUTXORing(wtxmgrNs, ringHash[:])
		if err != nil {
			return err
		}
		//find the index
		index := -1
		// We expected that when spent this utxo, the utxo ring will be update when add the script
		for k, sn := range u.OriginSerialNumberes {
			if bytes.Equal(sn, rec.MsgTx.TxIns[i].SerialNumber) {
				index = int(k)
				break
			}
		}
		if index == -1 { //it do not belong the wallet
			continue
		}
		//move from the unspentUtxo bucket to spentUtxobucket if necessary
		k := canonicalOutPointAbe(rec.MsgTx.TxIns[i].PreviousOutPointRing.OutPoints[index].TxHash, rec.MsgTx.TxIns[i].PreviousOutPointRing.OutPoints[index].Index)
		//v := wtxmgrNs.NestedReadWriteBucket(bucketUnspentTXO).Get(k)
		v := wtxmgrNs.NestedReadWriteBucket(bucketMaturedOutput).Get(k)
		if v == nil {
			return fmt.Errorf("there is no such a utxo in bucket")
		}
		// update the spendable balance
		spendableBal, err := fetchSpendableBalance(wtxmgrNs)
		if err != nil {
			return err
		}
		unconfirmedBal, err := fetchUnconfirmedBalance(wtxmgrNs)
		if err != nil {
			return err
		}

		utxo := &SpendableTXO{}
		err = utxo.Deserialize(&wire.OutPointAbe{
			TxHash: rec.MsgTx.TxIns[i].PreviousOutPointRing.OutPoints[index].TxHash,
			Index:  rec.MsgTx.TxIns[i].PreviousOutPointRing.OutPoints[index].Index,
		}, v)
		if err != nil {
			return err
		}

		amt := abeutil.Amount(utxo.Amount)
		spendableBal -= amt
		unconfirmedBal += amt
		err = putSpendableBalance(wtxmgrNs, spendableBal)
		if err != nil {
			return err
		}
		err = putUnconfirmedBalance(wtxmgrNs, unconfirmedBal)
		if err != nil {
			return err
		}
		err = deleteSpendableTXO(wtxmgrNs, k)
		if err != nil {
			return err
		}

		sbu := &UnconfirmedTXO{
			SpendableTXO: *utxo,
			SpentByHash:  rec.Hash,
			SpentTime:    time.Now(),
		}
		err = putUnconfirmedTXO(wtxmgrNs, sbu)
		if err != nil {
			return err
		}

		if utxo.IsCTAUTCoin() {
			autCoin, err := fetchRawCTAUTCoin(wtxmgrNs, utxo.TxOutput.TxHash, utxo.TxOutput.Index)
			if err != nil {
				return err
			}
			if autCoin.IsAUTRootCoin {
				autSpendableRootCoinNums, err := fetchCTAUTSpenableRootCoinNum(wtxmgrNs)
				if err != nil {
					return err
				}
				autUnconfirmedRootCoinNums, err := fetchCTAUTUnconfirmedRootCoinNum(wtxmgrNs)
				if err != nil {
					return err
				}

				autSpendableRootCoinNums[hex.EncodeToString(autCoin.AUTIdentifier)] -= 1
				autUnconfirmedRootCoinNums[hex.EncodeToString(autCoin.AUTIdentifier)] += 1

				err = putCTAUTSpenableRootCoinNum(wtxmgrNs, autSpendableRootCoinNums)
				if err != nil {
					return err
				}
				err = putCTAUTUnconfirmedRootCoinNum(wtxmgrNs, autUnconfirmedRootCoinNums)
				if err != nil {
					return err
				}
			} else {
				autSpendableBals, err := fetchCTAUTSpenableBalance(wtxmgrNs)
				if err != nil {
					return err
				}
				autUnconfirmedBals, err := fetchCTAUTUnconfirmedBalance(wtxmgrNs)
				if err != nil {
					return err
				}

				autSpendableBals[hex.EncodeToString(autCoin.AUTIdentifier)] -= autCoin.Value
				autUnconfirmedBals[hex.EncodeToString(autCoin.AUTIdentifier)] += autCoin.Value

				err = putAUTSpenableBalance(wtxmgrNs, autSpendableBals)
				if err != nil {
					return err
				}
				err = putAUTUnconfirmedBalance(wtxmgrNs, autUnconfirmedBals)
				if err != nil {
					return err
				}
			}
		}

		flag := false
		relevantTxs := existsRawReleventTxs(wtxmgrNs, k)
		if len(relevantTxs) != 0 {
			offset := 0
			for offset+chainhash.HashSize <= len(relevantTxs) {
				if bytes.Equal(rec.Hash[:], relevantTxs[offset:offset+chainhash.HashSize]) {
					flag = true
					err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
					if err != nil {
						return err
					}
					err = deleteRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
					if err != nil {
						return err
					}
					offset += chainhash.HashSize
					continue
				}
				// other conflict transaction should be marked invalid
				conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
				if len(conflictTx) != 0 {
					tx := new(TxRecord)
					err := tx.Deserialize(conflictTx)
					if err != nil {
						return err
					}
					// assert
					if !bytes.Equal(tx.Hash[:], relevantTxs[offset:offset+chainhash.HashSize]) {
						return fmt.Errorf("unmatched transaction %s in unconfirmed transaction bucket", tx.Hash)
					}

					err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
					if err != nil {
						return err
					}
					err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
					if err != nil {
						return err
					}
					txInfo := &TransactionInfo{
						TxHash: &tx.Hash,
						Height: s.manager.SyncedTo().Height,
					}
					s.NotifyTransactionInvalid(txInfo)
					log.Infof("send invalid transaction notification %v at height %d", txInfo.TxHash, txInfo.Height)
				}
				conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
				if len(conflictTx) != 0 {
					tx := new(TxRecord)
					err := tx.Deserialize(conflictTx)
					if err != nil {
						return err
					}
					// assert
					if !bytes.Equal(tx.Hash[:], relevantTxs[offset:offset+chainhash.HashSize]) {
						return fmt.Errorf("unmatched transaction %s in unconfirmed transaction bucket", tx.Hash)
					}

					err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
					if err != nil {
						return err
					}
					err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
					if err != nil {
						return err
					}
					txInfo := &TransactionInfo{
						TxHash: &tx.Hash,
						Height: s.manager.SyncedTo().Height,
					}
					s.NotifyTransactionInvalid(txInfo)
					log.Infof("send invalid transaction notification %v at height %d", txInfo.TxHash, txInfo.Height)
				}
				offset += chainhash.HashSize
			}
		}
		if !flag {
			relevantTxs = append(relevantTxs, rec.Hash[:]...)
			err = putRawRelevantTxs(wtxmgrNs, k, relevantTxs)
			if err != nil {
				return err
			}
		}
	}
	// add this transaction to unminedAbe bucket,and notify the index has spent
	v, err := valueTxRecord(rec)
	if err != nil {
		return err
	}
	err = putRawUnconfirmedTx(wtxmgrNs, rec.Hash[:], v)
	if err != nil {
		return err
	}
	txInfo := &TransactionInfo{
		TxHash: &rec.Hash,
		Height: s.manager.SyncedTo().Height,
	}
	s.NotifyTransactionRollback(txInfo)
	log.Infof("send unconfirmed transaction notification %v at height %d", txInfo.TxHash, txInfo.Height)
	return nil
}

func (s *Store) ReceiveTxo(txOut *wire.TxOutAbe, addrMgrNs walletdb.ReadWriteBucket) (valid bool, v uint64, addrKey []byte, publicRand []byte, privacyLevel abecryptoxkey.PrivacyLevel, err error) {
	// abecryptoxparam.CryptoSchemePQRingCTX
	privacyLevel, err = abecryptox.GetTxoPrivacyLevel(txOut)
	if err != nil {
		return false, 0, nil, nil, 0, err
	}
	if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre {
		return false, 0, nil, nil, 0, nil
	}

	_, _, valueRootSeed, detectorRootKey, err := s.manager.FetchProtectedRootSeeds(addrMgrNs)
	if err != nil {
		return false, 0, nil, nil, privacyLevel, err
	}

	valid, err = abecryptox.TxoCoinDetectByCoinDetectorRootKey(txOut, detectorRootKey)
	if err != nil {
		return false, 0, nil, nil, privacyLevel, err
	}

	if !valid {
		return false, 0, nil, nil, privacyLevel, err
	}

	valid, v, err = abecryptox.TxoCoinReceiveByRootSeeds(txOut, valueRootSeed, detectorRootKey)
	if err != nil {
		return false, 0, nil, nil, privacyLevel, err
	}

	coinAddr, err := abecryptox.ExtractCoinAddressFromTxo(txOut)
	if err != nil {
		return false, 0, nil, nil, 0, err
	}
	publicRand, err = abecryptox.ExtractPublicRandFromTxo(txOut)
	if err != nil {
		return false, 0, nil, nil, 0, err
	}
	// todo: Investigate the use of DoubleHashB/DoubleHashH (to SHA3-256) in Aconcagua upgrade
	return valid, v, chainhash.DoubleHashB(coinAddr), publicRand, privacyLevel, nil
}

func (s *Store) ReceiveCTAUTToken(txOut *wire.TxOutAbe, ctautTxo *ctautwire.AutTxo, addrMgrNs walletdb.ReadWriteBucket) (v uint64, err error) {
	// abecryptoxparam.CryptoSchemePQRingCTX
	privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
	if err != nil {
		return 0, err
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		return 0, nil
	}

	_, _, valueRootSeed, _, err := s.manager.FetchProtectedRootSeeds(addrMgrNs)
	if err != nil {
		return 0, err
	}

	publicRand, err := abecryptox.ExtractPublicRandFromTxo(txOut)
	if err != nil {
		return 0, err
	}
	coinValuePublicKey, coinSecretKey, err := abecryptoxkey.CoinValueKeyReGenByRootSeedsFromPublicRand(
		abecryptoxparam.CryptoSchemePQRingCTX,
		abecryptoxkey.PrivacyLevelPSEUDONYMCT,
		valueRootSeed, publicRand)
	return abecryptox.ExtractAutTxoValue(ctautTxo, coinValuePublicKey, coinSecretKey)
}
func (s *Store) GenSNForTxo(txOut *wire.TxOutAbe, addrMgrNs walletdb.ReadWriteBucket, ringHash chainhash.Hash, index uint8) ([]byte, error) {
	coinAddr, err := abecryptox.ExtractCoinAddressFromTxo(txOut)
	if err != nil {
		return nil, err
	}

	if s.manager.GetCryptoScheme() == abecryptoxparam.CryptoSchemePQRingCT {
		// fetch address
		_, _, addressSecretSnEnc, _, _, _, err := s.manager.FetchAddressKeyEnc(addrMgrNs, coinAddr)
		if err != nil {
			return nil, err
		}
		_, _, asksn, _, _, err := s.manager.DecryptAddressKey(nil, nil, addressSecretSnEnc, nil, nil)
		if err != nil {
			return nil, err
		}

		sn, err := abecryptox.TxoCoinSerialNumberGenByKey(txOut, ringHash, index, asksn)
		if err != nil {
			return nil, err
		}
		return sn, nil
	}

	privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
	if err != nil {
		return nil, err
	}
	if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
		return abecryptox.TxoCoinSerialNumberGenByRootSeed(txOut, ringHash, index, nil)
	}

	// abecryptoxkey.PrivacyLevelRINGCT
	_, snKeyRootSeed, _, _, err := s.manager.FetchProtectedRootSeeds(addrMgrNs)
	if err != nil {
		return nil, err
	}

	return abecryptox.TxoCoinSerialNumberGenByRootSeed(txOut, ringHash, index, snKeyRootSeed)
}
func (s *Store) InsertBlock(txMgrNs walletdb.ReadWriteBucket, addrMgrNs walletdb.ReadWriteBucket, block *BlockRecord, extraBlock map[uint32]*BlockRecord, maturedBlockHashs []*chainhash.Hash) error {
	log.Infof("Current sync height %d, hash %s", block.Height, block.Hash)

	balance, err := fetchMinedBalance(txMgrNs)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpendableBalance(txMgrNs)
	if err != nil {
		return err
	}
	immatureCBBal, err := fetchImmatureCoinbaseBalance(txMgrNs)
	if err != nil {
		return err
	}
	immatureTRBal, err := fetchImmatureTransferBalance(txMgrNs)
	if err != nil {
		return err
	}
	unconfirmedBal, err := fetchUnconfirmedBalance(txMgrNs)
	if err != nil {
		return err
	}

	ctautBalances, err := fetchCTAUTMinedBalance(txMgrNs)
	if err != nil {
		return err
	}
	ctautSpendableBal, err := fetchCTAUTSpenableBalance(txMgrNs)
	if err != nil {
		return err
	}
	ctautImmatureBal, err := fetchCTAUTImmatureTransferBalance(txMgrNs)
	if err != nil {
		return err
	}
	ctautUnconfirmedBal, err := fetchCTAUTUnconfirmedBalance(txMgrNs)
	if err != nil {
		return err
	}

	ctautRootCoinNum, err := fetchCTAUTRootCoinNum(txMgrNs)
	if err != nil {
		return err
	}
	ctautImmatureRootCoinNum, err := fetchCTAUTImmatureRootCoinNum(txMgrNs)
	if err != nil {
		return err
	}
	ctautSpendableRootCoinNum, err := fetchCTAUTSpenableRootCoinNum(txMgrNs)
	if err != nil {
		return err
	}
	ctautUnconfirmedRootCoinNum, err := fetchCTAUTUnconfirmedRootCoinNum(txMgrNs)
	if err != nil {
		return err
	}

	// put the serialized block into database
	err = putBlockRecord(txMgrNs, block)
	if err != nil {
		return err
	}

	// delete oldest block in the database
	// It assumes that the deleted block would not be reverted.
	if block.Height > NUMBERBLOCK {
		err = deleteRawBlockWithBlockHeight(txMgrNs, block.Height-NUMBERBLOCK)
		if err != nil {
			return err
		}
	}

	b := Block{
		Hash:   block.Hash,
		Height: block.Height,
	}

	coinbaseTx := block.TxRecords[0].MsgTx
	coinbaseOutput := make(map[wire.OutPointAbe]*SpendableTXO)
	blockOutputs := make(map[Block][]wire.OutPointAbe)

	// store all outputs of coinbaseTx which belong to us into a map : coinbaseOutput
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		valid, v, _, publicRand, privacyLevel, err := s.ReceiveTxo(coinbaseTx.TxOuts[i], addrMgrNs)
		if err != nil {
			return err
		}
		if valid {
			amt := abeutil.Amount(v)
			immatureCBBal += amt
			balance += amt
			// TODO: the transaction hash and index cannot be a unique key
			k := wire.OutPointAbe{
				TxHash: coinbaseTx.TxHash(),
				Index:  uint8(i),
			}
			tmp := NewUnspentUTXO(coinbaseTx.TxOuts[i].Version, b.Height, k,
				true, v, 0xFF, block.RecvTime, chainhash.ZeroHash, 0,
				privacyLevel, publicRand)

			coinbaseOutput[k] = tmp
			blockOutputs[b] = append(blockOutputs[b], k)

			log.Infof("(ABEL) Find coinbase txo (version %08x, hash %s, index %d) at block height %d (hash %s) with value %v ABEL (pseudonymous %t)",
				coinbaseTx.Version, coinbaseTx.TxHash(), i, block.Height, block.Hash, amt.ToABE(), tmp.IsPseudonymous())
		}
	}

	transferOutputs := make(map[wire.OutPointAbe]*SpendableTXO) // store the outputs which belong to the wallet
	var blockInputs *RingHashSerialNumbers                      // save the inputs which belong to the wallet spent by this block and store the increment and the utxo ring before adding this block
	relevantUTXORings := make(map[chainhash.Hash]*UTXORing)

	disabledAUTPoints := make([]*wire.OutPointAbe, 0, 100)

	// handle with the transfer transactions
	for i := 1; i < len(block.TxRecords); i++ { // trace every tx in this block
		txi := block.TxRecords[i].MsgTx
		txhash := txi.TxHash()

		ctAUTScript, err := ctaut.ExtractCTAUTScript(&txi)
		if err != nil {
			if !errors.Is(err, ctaut.ErrNonAutTx) {
				log.Warnf("extract transaction %s as aut transaction err:%s", txhash, err)
			}
		}

		// traverse all the inputs of a transaction
		// 1. add serial number to corresponding ring if needed
		// 2. move consumed txo to spentconfirmed bucket
		// TODO:need to check for this section
		consumeTxo := false
		for j := 0; j < len(txi.TxIns); j++ {
			serialNumber := txi.TxIns[j].SerialNumber

			// compute the ring hash of each input in every transaction to match the utxo in the database
			ringHash := txi.TxIns[j].PreviousOutPointRing.Hash()
			u, ok := relevantUTXORings[ringHash] // firstly, check it exist in relevantUTXORing
			if !ok {
				// TODO(abe):why in the bucket utxo ring, this entry which is keyed by ringHash is not found?
				key, value := existsUTXORing(txMgrNs, ringHash) // if not, check it the bucket
				if value == nil {                               //if not, it means that this input do not belong to wallet
					// if there is no value in utxo ring bucket.
					// the pointed output must not belong to the wallet
					continue
				}
				// if the ring hash exists in the database, fetch the utxo ring
				oldU, err := fetchUTXORing(txMgrNs, key) //get the value from utxoring bucket, it will be one coins of wallet
				// if the utxo ring is nil or the err is not nil, it means that the utxo ring of pointed output has consumed out.
				if oldU == nil || err != nil {
					return err
				}
				// match the serialNumber, just a check for database
				for k := 0; k < len(oldU.GotSerialNumberes); k++ {
					// check doubling serialNumber
					if bytes.Equal(serialNumber, oldU.GotSerialNumberes[k][:]) {
						log.Errorf("There has a same serialNumber in UTXORing")
						return fmt.Errorf("there has a same serialNumber in UTXORing")
					}
				}
				// save the previous utxoring for quick roll back
				if blockInputs == nil {
					blockInputs = new(RingHashSerialNumbers)
					blockInputs.utxoRings = make(map[chainhash.Hash]UTXORing)
					blockInputs.serialNumbers = make(map[chainhash.Hash][][]byte)
				}
				_, ok = blockInputs.utxoRings[ringHash]
				if !ok { // the utxo ring has not cached,record it in block input
					blockInputs.utxoRings[ringHash] = *oldU
				}
				u = oldU.Copy()
			}

			for index, sn := range u.OriginSerialNumberes {
				if !bytes.Equal(sn, serialNumber) {
					continue
				}

				// it means that the consumed input belongs wallet
				consumeTxo = true
				// add it's hash to relevant bucket
				k := canonicalOutPointAbe(u.TxHashes[index], u.OutputIndexes[index])
				txiHash := txi.TxHash()
				// read relevant transaction hashes
				relevantTxs := existsRawReleventTxs(txMgrNs, k)
				// check the current transaction is included or not in relevant transaction
				// remove the relevant except current transaction in unconfirmed bucket into invalid transaction bucket
				flag := false
				if len(relevantTxs) != 0 {
					offset := 0
					for offset+chainhash.HashSize <= len(relevantTxs) {
						if bytes.Equal(txiHash[:], relevantTxs[offset:offset+chainhash.HashSize]) {
							// it means that the wallet know the transaction
							flag = true
							offset += chainhash.HashSize
							continue
						}
						conflictTx := existsRawUnconfirmedTx(txMgrNs, relevantTxs[offset:offset+chainhash.HashSize])
						if len(conflictTx) != 0 {
							err = deleteRawUnconfirmedTx(txMgrNs, relevantTxs[offset:offset+chainhash.HashSize])
							if err != nil {
								return err
							}
							err = putRawInvalidTx(txMgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
							if err != nil {
								return err
							}
							txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
							// TODO(202211) send invalid notification to registered client
							s.NotifyTransactionInvalid(&TransactionInfo{
								TxHash: txHash,
								Height: block.Height,
							})
							log.Infof("send invalid transaction notification %v at height %d", txHash, block.Height)
						}
						offset += chainhash.HashSize
					}
				}
				if !flag {
					// add relevant relation: outpoint(txHash,Index) -> TxHash
					relevantTxs = append(relevantTxs, txiHash[:]...)
					err = putRawRelevantTxs(txMgrNs, k, relevantTxs)
					if err != nil {
						return err
					}
				}

				break
			}
			blockInputs.serialNumbers[ringHash] = append(blockInputs.serialNumbers[ringHash], serialNumber)
			// copy a new utxoring and update the new utxoring variable
			err := u.AddGotSerialNumber(serialNumber)
			if err != nil {
				return err
			}

			//update the relevantUTXORing
			relevantUTXORings[ringHash] = u
		}

		// it means current transaction consumes some txo belongs wallet
		// move it from unconfirmed/invalid bucket to confirmed bucket
		if consumeTxo {
			// delete from unconfirmed transaction set if exist
			if len(existsRawUnconfirmedTx(txMgrNs, txhash[:])) != 0 {
				err = deleteRawUnconfirmedTx(txMgrNs, txhash[:])
				if err != nil {
					return err
				}
			}
			// delete from invalid transaction set if exist
			if len(existsRawInvalidTx(txMgrNs, txhash[:])) != 0 {
				err = deleteRawInvalidTx(txMgrNs, txhash[:])
				if err != nil {
					return err
				}
			}

			// TODO(202211) send confirmed notification to registered client
			// and move to confirmed transaction set
			txRecord, err := NewTxRecordFromMsgTx(&txi, block.RecvTime)
			if err != nil {
				return err
			}
			v, err := valueTxRecord(txRecord)
			if err != nil {
				return err
			}
			err = putRawConfirmedTx(txMgrNs, txhash[:], v)
			if err != nil {
				return err
			}
			txHash := txi.TxHash()
			s.NotifyTransactionAccepted(&TransactionInfo{
				TxHash: &txHash,
				Height: block.Height,
			})
			log.Infof("send confirmed transaction notification %v at height %d", txHash, block.Height)
		}
		// update the utxo ring bucket
		for ringHash, utxoRing := range relevantUTXORings {
			//  move relevant utxo from unspentTXO or SpentButUnmined bucket to SpentConfirmTXO
			for t := 0; t < len(utxoRing.IsMy); t++ {
				// the outpoint owned by wallet is spent
				// it should be move to spent and confirmed bucket
				if utxoRing.IsMy[t] && utxoRing.Spent[t] {
					// it means that the transaction related to wallet
					k := canonicalOutPointAbe(utxoRing.TxHashes[t], utxoRing.OutputIndexes[t])
					// if this transaction is created by the wallet, the outpoint should be stored
					// in spentButUnmined bucket.
					// But if the wallet is restored, the outpoint should be in the matured bucket
					var confirmedTxo *ConfirmedTXO
					serializedTXO := existsSpendableTXO(txMgrNs, k)
					if serializedTXO != nil {
						// firstly deserialize the unspent txo
						txo := &SpendableTXO{}
						err = txo.Deserialize(&wire.OutPointAbe{
							TxHash: utxoRing.TxHashes[t],
							Index:  utxoRing.OutputIndexes[t],
						}, serializedTXO)
						if err != nil {
							return err
						}

						//otherwise it has been moved to spentButUnmined bucket
						// update the balances
						amt := abeutil.Amount(txo.Amount)
						balance -= amt
						spendableBal -= amt

						confirmedTxo = &ConfirmedTXO{
							UnconfirmedTXO: UnconfirmedTXO{
								SpendableTXO: *txo,
								SpentByHash:  txhash,
								SpentTime:    block.RecvTime,
							},
							ConfirmedByBlockHash: block.Hash,
							ConfirmTime:          block.RecvTime,
						}

						err = deleteSpendableTXO(txMgrNs, k)
						if err != nil {
							return err
						}

						log.Infof("(ABEL) Consumed txo (version %08x, hash %s, index %d, value %v ABEL,pseudonymous %t) at block height %d (hash %s)",
							txo.Version, txo.TxOutput.TxHash, txo.TxOutput.Index, amt.ToABE(), txo.IsPseudonymous(), block.Height, block.Hash)

						// update info about aut
						if txo.IsCTAUTCoin() {
							ctAUTToken, alreadySpent, err := spendCTAUTCoin(txMgrNs, txo.TxOutput.TxHash, txo.TxOutput.Index)
							if err != nil {
								return err
							}
							if !alreadySpent {
								if ctAUTToken.IsAUTRootCoin {
									ctautRootCoinNum[hex.EncodeToString(ctAUTToken.AUTIdentifier)] -= 1
									ctautSpendableRootCoinNum[hex.EncodeToString(ctAUTToken.AUTIdentifier)] -= 1
									log.Infof("(CTAUT) Consume root coin (identifer %s, hash %s, index %d) at block height %d (hash %s)",
										hex.EncodeToString(ctAUTToken.AUTIdentifier), ctAUTToken.TxOutput.TxHash, ctAUTToken.TxOutput.Index, block.Height, block.Hash)
								} else {

									ctautBalances[hex.EncodeToString(ctAUTToken.AUTIdentifier)] -= ctAUTToken.Value
									ctautSpendableBal[hex.EncodeToString(ctAUTToken.AUTIdentifier)] -= ctAUTToken.Value
									log.Infof("(CTAUT) Consume coin (identifer %s, hash %s, index %d) at block height %d (hash %s) with value %v",
										hex.EncodeToString(ctAUTToken.AUTIdentifier), ctAUTToken.TxOutput.TxHash, ctAUTToken.TxOutput.Index, block.Height, block.Hash, ctAUTToken.Value)
								}
							}
						}

					} else if serializedTXO = existsUnconfirmedTXO(txMgrNs, k); serializedTXO != nil {
						//otherwise it has been moved to spentButUnmined bucket
						// firstly deserialize the unspent txo
						txo := &UnconfirmedTXO{}
						err = txo.Deserialize(&wire.OutPointAbe{
							TxHash: utxoRing.TxHashes[t],
							Index:  utxoRing.OutputIndexes[t],
						}, serializedTXO)
						if err != nil {
							return err
						}

						amt := abeutil.Amount(txo.Amount)
						balance -= amt
						unconfirmedBal -= amt

						confirmedTxo = &ConfirmedTXO{
							UnconfirmedTXO:       *txo,
							ConfirmedByBlockHash: block.Hash,
							ConfirmTime:          block.RecvTime,
						}

						err = deleteUnconfirmedTXO(txMgrNs, k)
						if err != nil {
							return err
						}

						if txo.IsCoinbase() {
							log.Infof("(ABEL) Consumed coinbase txo (version %08x, hash %s, index %d, value %v ABEL,pseudonymous %t) at block height %d (hash %s)",
								txo.Version, txo.TxOutput.TxHash, txo.TxOutput.Index, amt.ToABE(), txo.IsPseudonymous(), block.Height, block.Hash)
						} else {
							log.Infof("(ABEL) Consumed transfer txo (version %08x, hash %s, index %d, value %v ABEL, pseudonymous %t) at block height %d (hash %s)",
								txo.Version, txo.TxOutput.TxHash, txo.TxOutput.Index, amt.ToABE(), txo.IsPseudonymous(), block.Height, block.Hash)
						}

						// update info about aut
						if txo.IsCTAUTCoin() {
							spentAUTCoin, alreadySpent, err := spendCTAUTCoin(txMgrNs, txo.TxOutput.TxHash, txo.TxOutput.Index)
							if err != nil {
								return err
							}
							if !alreadySpent {
								if spentAUTCoin.IsAUTRootCoin {
									ctautRootCoinNum[hex.EncodeToString(spentAUTCoin.AUTIdentifier)] -= 1
									ctautUnconfirmedRootCoinNum[hex.EncodeToString(spentAUTCoin.AUTIdentifier)] -= 1
									log.Infof("(CTAUT) Consume root coin (identifer %s, hash %s, index %d) at block height %d (hash %s)",
										hex.EncodeToString(spentAUTCoin.AUTIdentifier), spentAUTCoin.TxOutput.TxHash, spentAUTCoin.TxOutput.Index, block.Height, block.Hash)
								} else {
									ctautBalances[hex.EncodeToString(spentAUTCoin.AUTIdentifier)] -= spentAUTCoin.Value
									ctautUnconfirmedBal[hex.EncodeToString(spentAUTCoin.AUTIdentifier)] -= spentAUTCoin.Value
									log.Infof("(CTAUT) Consume coin (identifer %s, hash %s, index %d) at block height %d (hash %s) with value %v",
										hex.EncodeToString(spentAUTCoin.AUTIdentifier), spentAUTCoin.TxOutput.TxHash, spentAUTCoin.TxOutput.Index, block.Height, block.Hash, spentAUTCoin.Value)
								}
							}
						}
					} else {
						log.Errorf("Do not find txo in spendable txo bucket or unconfirmed txo bucket")
					}
					// move to spent and confirm bucket
					if serializedTXO != nil {
						err := putConfirmedTXO(txMgrNs, confirmedTxo)
						if err != nil {
							return err
						}
					}
				}
			}

			if utxoRing.AllSpent {
				// if all outpoints have been spent, so this utxo ring will be deleted,
				// and mark deleted flag in ring bucket
				err := deleteUTXORing(txMgrNs, ringHash[:])
				if err != nil {
					return err
				}
				err = updateDeletedHeightRingDetails(txMgrNs, ringHash, block.Height)
				if err != nil {
					return err
				}
				continue
			}
			// if not, update the entry
			err := putUTXORing(txMgrNs, ringHash, utxoRing)
			if err != nil {
				return err
			}
		}

		// traverse all outputs of a transaction and check if it is ours
		for j := 0; j < len(txi.TxOuts); j++ {
			valid, v, addrKey, publicRand, privacyLevel, err := s.ReceiveTxo(txi.TxOuts[j], addrMgrNs)
			if err != nil {
				return err
			}
			if valid {
				amt := abeutil.Amount(v)
				immatureTRBal += amt
				balance += amt
				k := wire.OutPointAbe{
					TxHash: txi.TxHash(),
					Index:  uint8(j),
				}
				tmp := NewUnspentUTXO(txi.TxOuts[j].Version, b.Height, k,
					false, v, 0xFF, block.RecvTime, chainhash.ZeroHash, 0,
					privacyLevel, publicRand)
				transferOutputs[k] = tmp
				blockOutputs[b] = append(blockOutputs[b], k)

				log.Infof("(ABEL) Find transfer txo (version %08x, hash %s, index %d) at block height %d (hash %s) with value %v ABEL (pseudonymous %t)",
					txi.Version, txi.TxHash(), j, block.Height, block.Hash, amt.ToABE(), tmp.IsPseudonymous())

				if ctAUTScript != nil {
					identifier := ctAUTScript.Identifier()
					generatedTokens := ctAUTScript.GeneratedTokens()
					for t := 0; t < len(generatedTokens); t++ {
						token := generatedTokens[t]
						if token.HostOutPoint.Index == uint32(j) {
							tmp.PackedFlag |= txoFlagCTAUTCoin

							isAUTRootCoin := ctAUTScript.Type() == ctaut.Registration ||
								ctAUTScript.Type() == ctaut.ReRegistration

							var autTxoType abecryptox.AutTxoType
							var value uint64
							if !isAUTRootCoin {
								ctautTxo := &ctautwire.AutTxo{
									Version:   txi.Version,
									TxoScript: token.ValueScript,
								}
								autTxoType, err = abecryptox.GetAutTxoType(ctautTxo)
								if err != nil {
									return err
								}
								value, err = s.ReceiveCTAUTToken(txi.TxOuts[j], ctautTxo, addrMgrNs)
								if err != nil {
									return err
								}
							}
							token := NewCTAUTCoin(k, block.Height, identifier[:], isAUTRootCoin, autTxoType, token.ValueScript, value, addrKey, publicRand)
							err = putRawCTAUTCoin(txMgrNs, k.TxHash, k.Index, token)
							if err != nil {
								return err
							}

							if token.IsAUTRootCoin {
								ctautRootCoinNum[hex.EncodeToString(token.AUTIdentifier)] += 1
								ctautImmatureRootCoinNum[hex.EncodeToString(token.AUTIdentifier)] += 1
								log.Infof("(CTAUT) Find root coin (identifer %s, hash %s, index %d) at block height %d (hash %s)",
									hex.EncodeToString(token.AUTIdentifier), token.TxOutput.TxHash, token.TxOutput.Index, block.Height, block.Hash)
							} else {
								ctautBalances[hex.EncodeToString(token.AUTIdentifier)] += token.Value
								ctautImmatureBal[hex.EncodeToString(token.AUTIdentifier)] += token.Value
								log.Infof("(CTAUT) Find coin (identifer %s, hash %s, index %d) at block height %d (hash %s) with value %v",
									hex.EncodeToString(token.AUTIdentifier), token.TxOutput.TxHash, token.TxOutput.Index, block.Height, block.Hash, token.Value)
							}

							break
						}
					}
				}
			}
		}

		// if the type of aut transaction is re-registration, need to consume exist root coin
		if ctAUTScript != nil && ctAUTScript.Type() == ctaut.ReRegistration {
			identifier := ctAUTScript.Identifier()
			remainRootCoins, _, err := s.UnspentOutputsCTAUT(txMgrNs, identifier[:], true)
			if err != nil {
				return err
			}
			for _, remainRootCoin := range remainRootCoins {
				if !txhash.IsEqual(&remainRootCoin.TxOutput.TxHash) {
					_, alreadySpent, err := spendCTAUTCoin(txMgrNs, remainRootCoin.TxOutput.TxHash, remainRootCoin.TxOutput.Index)
					if err != nil {
						return err
					}
					if alreadySpent {
						continue
					}
					ctautRootCoinNum[hex.EncodeToString(remainRootCoin.AUTIdentifier)] -= 1
					ctautSpendableRootCoinNum[hex.EncodeToString(remainRootCoin.AUTIdentifier)] -= 1
					log.Infof("(CTAUT) Disable root coin (identifer %s, hash %s, index %d) at block height %d (hash %s) due to re-register aut transation",
						hex.EncodeToString(remainRootCoin.AUTIdentifier), remainRootCoin.TxOutput.TxHash, remainRootCoin.TxOutput.Index, block.Height, block.Hash)
					disabledAUTPoints = append(disabledAUTPoints, &remainRootCoin.TxOutput)
				}
			}
		}
	}

	// store the inputs of block for quick rollback
	if blockInputs != nil {
		err = putBlockInputs(txMgrNs, block.Height, block.Hash, blockInputs)
		if err != nil {
			return err
		}
	}

	if len(disabledAUTPoints) != 0 {
		err = putBlockDisabledAUTRootCoins(txMgrNs, block.Height, block.Hash, disabledAUTPoints)
		if err != nil {
			return err
		}
	}

	// store the output of block for quick rollback
	// TODO: there just is a block, so the map:block -> is useless
	if len(blockOutputs) != 0 { //add the block outputs in to bucket block outputs
		for blk, ops := range blockOutputs {
			err := putBlockOutputs(txMgrNs, blk.Height, blk.Hash, ops)
			if err != nil {
				return err
			}
		}
	}

	// move matured coinbase outputs to maturedOutput bucket
	blockNum := int32(wire.GetBlockNumPerRingGroupByBlockHeight(block.Height))
	maturity := int32(s.chainParams.CoinbaseMaturity)
	if block.Height >= maturity && (block.Height-maturity+1)%blockNum == 0 {
		for i := 0; i < len(maturedBlockHashs); i++ {
			utxoHeight := block.Height - maturity - int32(i)
			utxos, err := fetchImmatureCoinbaseOutput(txMgrNs, utxoHeight, *maturedBlockHashs[i])
			if err != nil {
				return err
			}
			for _, utxo := range utxos {
				utxo.PackedFlag |= txoFlagCoinbase
				err = putSpendableTXO(txMgrNs, utxo)
				if err != nil {
					return err
				}

				amt := abeutil.Amount(utxo.Amount)
				spendableBal += amt
				immatureCBBal -= amt
				log.Infof("(ABEL) Coinbase txo (version %08x, hash %s, index %d) at Height %d (Hash %s) , Value %v (pseudonymous %t) is matured!",
					utxo.Version, utxo.TxOutput.TxHash, utxo.TxOutput.Index, utxo.Height, maturedBlockHashs[i], amt.ToABE(), utxo.IsPseudonymous())

				// impossible for aut in coinbase transaction
			}
			err = deleteImmatureCoinbaseOutput(txMgrNs, canonicalBlock(utxoHeight, *maturedBlockHashs[i]))
			if err != nil {
				return err
			}
		}

	}

	// fetch the outputs of recent three blocks and form rings
	// move matured transfer outputs of previous two blocks to maturedOutput bucket
	// TODO(abe): check the correctness of generating ring and modify the utxo in bucket unspentUtxo
	if block.Height%blockNum == blockNum-1 {
		var block1CoinbaseUTXO, block1TransferUTXO, block0CoinbaseUTXO, block0TransferUTXO map[wire.OutPointAbe]*SpendableTXO
		// if the height is match, it need to generate the utxo ring
		// if the number of utxo in previous two block is not zero, take it
		msgBlock2 := block.MsgBlock
		block1Outputs, err := fetchBlockOutput(txMgrNs, block.Height-1, msgBlock2.Header.PrevBlock)
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		if block1Outputs != nil {
			block1CoinbaseUTXO, err = fetchImmatureCoinbaseOutput(txMgrNs, block.Height-1, msgBlock2.Header.PrevBlock)
			if err != nil {
				return err
			}
			block1TransferUTXO, err = fetchImmatureOutput(txMgrNs, block.Height-1, msgBlock2.Header.PrevBlock)
			if err != nil {
				return err
			}
		}
		var msgBlock1 *wire.MsgBlockAbe
		block1Record, err := fetchBlockRecord(txMgrNs, block.Height-1, msgBlock2.Header.PrevBlock)
		if err != nil || block1Record == nil {
			msgBlock1 = &extraBlock[uint32(block.Height-1)].MsgBlock
			err = putBlockRecord(txMgrNs, extraBlock[uint32(block.Height-1)])
			if err != nil {
				return err
			}
		} else {
			msgBlock1 = &block1Record.MsgBlock
		}

		block0Outputs, err := fetchBlockOutput(txMgrNs, block.Height-2, msgBlock1.Header.PrevBlock)
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		if block0Outputs != nil {
			block0CoinbaseUTXO, err = fetchImmatureCoinbaseOutput(txMgrNs, block.Height-2, msgBlock1.Header.PrevBlock)
			if err != nil {
				return err
			}
			block0TransferUTXO, err = fetchImmatureOutput(txMgrNs, block.Height-2, msgBlock1.Header.PrevBlock)
			if err != nil {
				return err
			}
		}

		// if there is zero output in three block belongs to the wallet, we return
		if len(coinbaseOutput) == 0 && len(transferOutputs) == 0 &&
			len(block1CoinbaseUTXO) == 0 && len(block1TransferUTXO) == 0 &&
			len(block0CoinbaseUTXO) == 0 && len(block0TransferUTXO) == 0 {
			// return handle
			err = putSpendableBalance(txMgrNs, spendableBal)
			if err != nil {
				return err
			}
			err = putImmatureCoinbaseBalance(txMgrNs, immatureCBBal)
			if err != nil {
				return err
			}
			err = putImmatureTransferBalance(txMgrNs, immatureTRBal)
			if err != nil {
				return err
			}
			err = putUnconfirmedBalance(txMgrNs, unconfirmedBal)
			if err != nil {
				return err
			}
			err = putMinedBalance(txMgrNs, balance)
			if err != nil {
				return err
			}

			err = putCTAUTImmatureRootCoinNum(txMgrNs, ctautImmatureRootCoinNum)
			if err != nil {
				return err
			}
			err = putCTAUTSpenableRootCoinNum(txMgrNs, ctautSpendableRootCoinNum)
			if err != nil {
				return err
			}
			err = putCTAUTUnconfirmedRootCoinNum(txMgrNs, ctautUnconfirmedRootCoinNum)
			if err != nil {
				return err
			}
			err = putCTAUTRootCoinNum(txMgrNs, ctautRootCoinNum)
			if err != nil {
				return err
			}

			err = putCTAUTImmatureTransferBalance(txMgrNs, ctautImmatureBal)
			if err != nil {
				return err
			}
			err = putCTAUTSpenableBalance(txMgrNs, ctautSpendableBal)
			if err != nil {
				return err
			}
			err = putCTAUTUnconfirmedBalance(txMgrNs, ctautUnconfirmedBal)
			if err != nil {
				return err
			}
			err = putCTAUTMinedBalance(txMgrNs, ctautBalances)
			if err != nil {
				return err
			}

			return nil
		}

		// generate the utxoring
		var msgBlock0 *wire.MsgBlockAbe
		block0Record, err := fetchBlockRecord(txMgrNs, block.Height-2, msgBlock1.Header.PrevBlock)
		if err != nil || block0Record == nil {
			msgBlock0 = &extraBlock[uint32(block.Height-2)].MsgBlock
			err = putBlockRecord(txMgrNs, extraBlock[uint32(block.Height-2)])
			if err != nil {
				return err
			}
		} else {
			msgBlock0 = &block0Record.MsgBlock
		}

		if msgBlock0 == nil || msgBlock1 == nil {
			return fmt.Errorf("newUtxoRingEntries is called with node that does not have 2 previous successive blocks in database")
		}

		block0 := abeutil.NewBlockAbe(msgBlock0) // height % 3 = 0
		block0.SetHeight(block.Height - 2)
		block1 := abeutil.NewBlockAbe(msgBlock1) // height %3 = 1
		block1.SetHeight(block.Height - 1)
		block2 := abeutil.NewBlockAbe(&msgBlock2) // height % 3 = 2
		block2.SetHeight(block.Height)
		blocks := []*abeutil.BlockAbe{block0, block1, block2}
		//ringBlockHeight := blocks[2].Height()
		blocksNum := len(blocks)
		blockHashs := make([]*chainhash.Hash, blocksNum)
		coinBaseRmTxoNum := 0
		transferRmTxoNum := 0
		for i := 0; i < blocksNum; i++ {
			blockHashs[i] = blocks[i].Hash()
			coinBaseRmTxoNum += len(blocks[i].Transactions()[0].MsgTx().TxOuts)
			for _, tx := range blocks[i].Transactions()[1:] {
				transferRmTxoNum += len(tx.MsgTx().TxOuts)
			}
		}
		ringBlockHeight := block.Height

		//create a view to generate the all rings
		txoRingSize := int(wire.GetTxoRingSizeByBlockHeight(block.Height))
		// newTxoRings, err := blockchain.BuildTxoRingsMLP(int(blockNum), txoRingSize, blocks)
		newTxoRings, err := blockchain.BuildTxoRingsAconcagua(int(blockNum), txoRingSize, blocks)
		if err != nil {
			return err
		}

		entries := map[chainhash.Hash]*blockchain.UtxoRingEntry{}
		for ringId, txoRing := range newTxoRings {
			if _, ok := entries[ringId]; ok {
				err = fmt.Errorf("InsertBlock: Found a hash collision (by RingId) when calling newUtxoRingEntriesMLP with blocks (hash %v, ringHeight %d, ringId %v)",
					block.Hash, ringBlockHeight, ringId)
				return err
			}
			newUtxoRingEntry := blockchain.InitNewUtxoRingEntryMLP(txoRing)
			entries[ringId] = newUtxoRingEntry
		}

		willAddUTXORing := make(map[chainhash.Hash]*UTXORing)
		willAddRing := make(map[chainhash.Hash]*Ring)
		for ringHash, utxoRingEntry := range entries {
			for _, outpoint := range utxoRingEntry.OutPointRing().OutPoints {
				var utxo *SpendableTXO
				var curMap int
				var ok bool
				if utxo, ok = coinbaseOutput[*outpoint]; ok {
					curMap = 1
				} else if utxo, ok = transferOutputs[*outpoint]; ok {
					curMap = 2
				} else if utxo, ok = block1CoinbaseUTXO[*outpoint]; ok {
					curMap = 3
				} else if utxo, ok = block1TransferUTXO[*outpoint]; ok {
					curMap = 4
				} else if utxo, ok = block0CoinbaseUTXO[*outpoint]; ok {
					curMap = 5
				} else if utxo, ok = block0TransferUTXO[*outpoint]; ok {
					curMap = 6
				}

				if utxo != nil { // this ring has utxo belonging to the wallet
					utxoRing, ok1 := willAddUTXORing[ringHash]
					if !ok1 {
						// add this ring and utxo ring to database
						//generate a ringDetails
						ring := Ring{}
						ring.Version = utxoRingEntry.Version
						if utxoRingEntry.IsCoinBase() {
							ring.PackedFlag |= ringFlagCoinbase
						}
						outpointRing := utxoRingEntry.OutPointRing()
						for i := 0; i < len(outpointRing.BlockHashs); i++ {
							ring.BlockHashes = append(ring.BlockHashes, *outpointRing.BlockHashs[i])
						}
						for i := 0; i < len(outpointRing.OutPoints); i++ {
							ring.TxHashes = append(ring.TxHashes, outpointRing.OutPoints[i].TxHash)
							ring.Index = append(ring.Index, outpointRing.OutPoints[i].Index)
						}
						privacyLevel := abecryptoxkey.PrivacyLevelPSEUDONYM + 1
						txOuts := utxoRingEntry.TxOuts()
						for i := 0; i < len(txOuts); i++ {
							ring.TxoScripts = append(ring.TxoScripts, txOuts[i].TxoScript)
							txoPrivacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOuts[i])
							if err != nil {
								return err
							}
							if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM+1 {
								privacyLevel = txoPrivacyLevel
							}
							if txoPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
								if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
									return fmt.Errorf("wrong ring formed")
								}
							} else {
								if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
									return fmt.Errorf("wrong ring formed")
								}
							}
						}
						if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
							ring.PackedFlag |= ringFlagPseudonymous
						}

						//generate the utxoring, then add it to wllAddUTXORing for updating
						utxoRing, err = NewUTXORingFromRing(&ring, ringHash)
						if err != nil {
							return err
						}
						willAddUTXORing[ringHash] = utxoRing
						willAddRing[ringHash] = &ring
					}
					utxo.RingHash = ringHash
					utxo.RingSize = uint8(len(utxoRing.TxHashes))
					switch curMap {
					case 1:
						coinbaseOutput[*outpoint] = utxo
					case 2:
						transferOutputs[*outpoint] = utxo
					case 3:
						block1CoinbaseUTXO[*outpoint] = utxo
					case 4:
						block1TransferUTXO[*outpoint] = utxo
					case 5:
						block0CoinbaseUTXO[*outpoint] = utxo
					case 6:
						block0TransferUTXO[*outpoint] = utxo
					default:
						panic("do not know where is from")
					}

					//update the utxo ring
					index := 0
					for ; index < len(utxoRing.TxHashes); index++ {
						if outpoint.TxHash.IsEqual(&utxoRing.TxHashes[index]) &&
							outpoint.Index == utxoRing.OutputIndexes[index] {
							break
						}
					}
					utxo.RingIndex = uint8(index)
					utxoRing.IsMy[index] = true

					// update the serialNumber
					ring := willAddRing[ringHash]
					sn, err := s.GenSNForTxo(wire.NewTxOutAbe(ring.Version, ring.TxoScripts[index]), addrMgrNs, utxoRing.RingHash, uint8(index))
					if err != nil {
						return err
					}
					if utxoRing.OriginSerialNumberes == nil {
						utxoRing.OriginSerialNumberes = make(map[uint8][]byte)
					}
					utxoRing.OriginSerialNumberes[uint8(index)] = sn
				}
			}
		}
		// put the utxo ring into database
		for ringHash, utxoRing := range willAddUTXORing {
			err = putUTXORing(txMgrNs, ringHash, utxoRing)
			if err != nil {
				return err
			}
			// put the ring to coinbase
			err = putRingDetails(txMgrNs, ringHash, willAddRing[ringHash])
			if err != nil {
				return err
			}
		}

		// coinbase output -> immature
		if len(block1CoinbaseUTXO) != 0 {
			err := putImmatureCoinbaseOutput(txMgrNs, block1.Height(), *block1.Hash(), block1CoinbaseUTXO)
			if err != nil {
				return err
			}
		}
		if len(block0CoinbaseUTXO) != 0 {
			err := putImmatureCoinbaseOutput(txMgrNs, block0.Height(), *block0.Hash(), block0CoinbaseUTXO)
			if err != nil {
				return err
			}
		}
		// transfer output -> mature
		for _, utxo := range block1TransferUTXO {
			err = putSpendableTXO(txMgrNs, utxo)
			if err != nil {
				return err
			}

			amt := abeutil.Amount(utxo.Amount)
			spendableBal += amt
			immatureTRBal -= amt

			log.Infof("(ABEL) Transfer txo (version %08x, hash %s, index %d) at Height %d (Hash %s) , Value %v (pseudonymous %t) is matured!",
				utxo.Version, utxo.TxOutput.TxHash, utxo.TxOutput.Index, utxo.Height, msgBlock1.BlockHash(), amt.ToABE(), utxo.IsPseudonymous())
			if utxo.IsCTAUTCoin() {
				token, err := fetchRawCTAUTCoin(txMgrNs, utxo.TxOutput.TxHash, utxo.TxOutput.Index)
				if err != nil {
					return err
				}
				if token.IsAUTRootCoin {
					ctautSpendableRootCoinNum[hex.EncodeToString(token.AUTIdentifier)] += 1
					ctautImmatureRootCoinNum[hex.EncodeToString(token.AUTIdentifier)] -= 1
					log.Infof("(CTAUT) root coin at Height %d (Hash %s) for AUT (identifer %s) is matured!",
						utxo.Height, msgBlock1.BlockHash(), hex.EncodeToString(token.AUTIdentifier))
				} else {
					ctautSpendableBal[hex.EncodeToString(token.AUTIdentifier)] += token.Value
					ctautImmatureBal[hex.EncodeToString(token.AUTIdentifier)] -= token.Value
					log.Infof("(CTAUT) coin at Height %d (Hash %s) for AUT (identifer %s) value %v is matured!",
						utxo.Height, msgBlock1.BlockHash(), hex.EncodeToString(token.AUTIdentifier), token.Value)
				}
			}
		}
		err = deleteImmatureOutput(txMgrNs, canonicalBlock(block.Height-1, msgBlock2.Header.PrevBlock))
		if err != nil {
			return err
		}

		for op, utxo := range block0TransferUTXO {
			err = putSpendableTXO(txMgrNs, utxo)
			if err != nil {
				return err
			}

			amt := abeutil.Amount(utxo.Amount)
			spendableBal += amt
			immatureTRBal -= amt

			log.Infof("(ABEL) Transfer txo (version %08x, hash %s, index %d) at Height %d (Hash %s) , Value %v (pseudonymous %t) is matured!",
				utxo.Version, utxo.TxOutput.TxHash, utxo.TxOutput.Index, utxo.Height, msgBlock0.BlockHash(), amt.ToABE(), utxo.IsPseudonymous())
			if utxo.IsCTAUTCoin() {
				token, err := fetchRawCTAUTCoin(txMgrNs, op.TxHash, op.Index)
				if err != nil {
					return err
				}
				if token.IsAUTRootCoin {
					ctautSpendableRootCoinNum[hex.EncodeToString(token.AUTIdentifier)] += 1
					ctautImmatureRootCoinNum[hex.EncodeToString(token.AUTIdentifier)] -= 1
					log.Infof("(CTAUT) root coin at Height %d (Hash %s) for AUT (identifer %s) is matured!",
						utxo.Height, msgBlock0.BlockHash(), hex.EncodeToString(token.AUTIdentifier))
				} else {
					ctautSpendableBal[hex.EncodeToString(token.AUTIdentifier)] += token.Value
					ctautImmatureBal[hex.EncodeToString(token.AUTIdentifier)] -= token.Value
					log.Infof("(CTAUT) coin at Height %d (Hash %s) for AUT (identifer %s) value %v is matured!",
						utxo.Height, msgBlock0.BlockHash(), hex.EncodeToString(token.AUTIdentifier), token.Value)
				}
			}

		}
		err = deleteImmatureOutput(txMgrNs, canonicalBlock(block.Height-2, msgBlock1.Header.PrevBlock))
		if err != nil {
			return err
		}
	}

	// store the coinbase outputs of current block
	if len(coinbaseOutput) != 0 {
		err := putImmatureCoinbaseOutput(txMgrNs, block.Height, block.Hash, coinbaseOutput)
		if err != nil {
			return err
		}
	}

	// move the matured transfer outputs to maturedOutput bucket
	if block.Height%blockNum == blockNum-1 {
		for _, utxo := range transferOutputs {
			err = putSpendableTXO(txMgrNs, utxo)
			if err != nil {
				return err
			}
			amt := abeutil.Amount(utxo.Amount)
			spendableBal += amt
			immatureTRBal -= amt

			log.Infof("(ABEL) Transfer txo (version %08x, hash %s, index %d) at Height %d (Hash %s) , Value %v (pseudonymous %t) is matured!",
				utxo.Version, utxo.TxOutput.TxHash, utxo.TxOutput.Index, utxo.Height, block.Hash, amt.ToABE(), utxo.IsPseudonymous())
			if utxo.IsCTAUTCoin() {
				token, err := fetchRawCTAUTCoin(txMgrNs, utxo.TxOutput.TxHash, utxo.TxOutput.Index)
				if err != nil {
					return err
				}
				if token.IsAUTRootCoin {
					ctautSpendableRootCoinNum[hex.EncodeToString(token.AUTIdentifier)] += 1
					ctautImmatureRootCoinNum[hex.EncodeToString(token.AUTIdentifier)] -= 1
					log.Infof("(CTAUT) root coin at Height %d (Hash %s) for AUT (identifer %s) is matured!",
						utxo.Height, block.Hash, hex.EncodeToString(token.AUTIdentifier))
				} else {
					ctautSpendableBal[hex.EncodeToString(token.AUTIdentifier)] += token.Value
					ctautImmatureBal[hex.EncodeToString(token.AUTIdentifier)] -= token.Value
					log.Infof("(CTAUT) coin at Height %d (Hash %s) for AUT (identifer %s) value %v is matured!",
						utxo.Height, block.Hash, hex.EncodeToString(token.AUTIdentifier), token.Value)
				}
			}
		}
	} else { // immatured
		if len(transferOutputs) != 0 {
			err = putImmatureOutput(txMgrNs, block.Height, block.Hash, transferOutputs)
			if err != nil {
				return err
			}
		}
	}

	// update the balances
	// return handle
	err = putSpendableBalance(txMgrNs, spendableBal)
	if err != nil {
		return err
	}
	err = putImmatureCoinbaseBalance(txMgrNs, immatureCBBal)
	if err != nil {
		return err
	}
	err = putImmatureTransferBalance(txMgrNs, immatureTRBal)
	if err != nil {
		return err
	}
	err = putUnconfirmedBalance(txMgrNs, unconfirmedBal)
	if err != nil {
		return err
	}
	err = putMinedBalance(txMgrNs, balance)
	if err != nil {
		return err
	}

	err = putCTAUTImmatureRootCoinNum(txMgrNs, ctautImmatureRootCoinNum)
	if err != nil {
		return err
	}
	err = putCTAUTSpenableRootCoinNum(txMgrNs, ctautSpendableRootCoinNum)
	if err != nil {
		return err
	}
	err = putCTAUTUnconfirmedRootCoinNum(txMgrNs, ctautUnconfirmedRootCoinNum)
	if err != nil {
		return err
	}
	err = putCTAUTRootCoinNum(txMgrNs, ctautRootCoinNum)
	if err != nil {
		return err
	}

	err = putCTAUTImmatureTransferBalance(txMgrNs, ctautImmatureBal)
	if err != nil {
		return err
	}
	err = putCTAUTSpenableBalance(txMgrNs, ctautSpendableBal)
	if err != nil {
		return err
	}
	err = putAUTUnconfirmedBalance(txMgrNs, ctautUnconfirmedBal)
	if err != nil {
		return err
	}
	err = putAUTMinedBalance(txMgrNs, ctautBalances)
	if err != nil {
		return err
	}

	return nil
}
func (s *Store) InsertGenesisBlock(txMgrNs walletdb.ReadWriteBucket, addrMgrNs walletdb.ReadWriteBucket, block *BlockRecord) error {
	balance, err := fetchMinedBalance(txMgrNs)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpendableBalance(txMgrNs)
	if err != nil {
		return err
	}
	immatureCBBal, err := fetchImmatureCoinbaseBalance(txMgrNs)
	if err != nil {
		return err
	}
	immatureTRBal, err := fetchImmatureTransferBalance(txMgrNs)
	if err != nil {
		return err
	}
	unconfirmedBal, err := fetchUnconfirmedBalance(txMgrNs)
	if err != nil {
		return err
	}

	// put the genesis block into database
	err = putBlockRecord(txMgrNs, block)
	if err != nil {
		return err
	}
	b := Block{
		Hash:   block.Hash,
		Height: block.Height,
	}
	blockOutputs := make(map[Block][]wire.OutPointAbe) // if the block height meet the requirement, it also store previous two block outputs belong the wallet

	coinbaseTx := block.TxRecords[0].MsgTx
	coinbaseOutput := make(map[wire.OutPointAbe]*SpendableTXO)
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		success, value, _, publicRand, _, err := s.ReceiveTxo(coinbaseTx.TxOuts[i], addrMgrNs)
		if err != nil {
			return err
		}
		if success {
			amt := abeutil.Amount(value)
			log.Infof("(Coinbase) Find txo (hash %s, index %d) at block height %d (hash %s) with value %v",
				coinbaseTx.TxHash(), i, block.Height, block.Hash, amt.ToABE())
			immatureCBBal += amt
			balance += amt
			outpoint := wire.OutPointAbe{
				TxHash: coinbaseTx.TxHash(),
				Index:  uint8(i),
			}
			tmp := NewUnspentUTXO(
				coinbaseTx.TxOuts[i].Version, b.Height, outpoint,
				true, value,
				0xFF, block.RecvTime, chainhash.ZeroHash, 0,
				abecryptoxkey.PrivacyLevelRINGCTPre, publicRand)
			coinbaseOutput[outpoint] = tmp
			blockOutputs[b] = append(blockOutputs[b], outpoint)
		}
	}
	if len(blockOutputs) != 0 {
		err := putImmatureCoinbaseOutput(txMgrNs, block.Height, block.Hash, coinbaseOutput)
		if err != nil {
			return err
		}
	}
	// in the other hand, genesis block has ONLY coinbase transaction
	// so output would be in coinbase transaction if exist
	if len(blockOutputs) != 0 { //add the block outputs in to bucket block outputs
		for blk, ops := range blockOutputs {
			err = putBlockOutputs(txMgrNs, blk.Height, blk.Hash, ops)
			if err != nil {
				return err
			}
		}
	}
	// update the balances
	err = putSpendableBalance(txMgrNs, spendableBal)
	if err != nil {
		return err
	}
	err = putImmatureCoinbaseBalance(txMgrNs, immatureCBBal)
	if err != nil {
		return err
	}
	err = putImmatureTransferBalance(txMgrNs, immatureTRBal)
	if err != nil {
		return err
	}
	err = putUnconfirmedBalance(txMgrNs, unconfirmedBal)
	if err != nil {
		return err
	}
	return putMinedBalance(txMgrNs, balance)
}

// RemoveUnminedTx attempts to remove an unmined transaction from the
// transaction store. This is to be used in the scenario that a transaction
// that we attempt to rebroadcast, turns out to double spend one of our
// existing inputs. This function we remove the conflicting transaction
// identified by the tx record, and also recursively remove all transactions
// that depend on it.

// insertMinedTx inserts a new transaction record for a mined transaction into
// the database under the confirmed bucket. It guarantees that, if the
// tranasction was previously unconfirmed, then it will take care of cleaning up
// the unconfirmed state. All other unconfirmed double spend attempts will be
// removed as well.

// AddCredit marks a transaction record as containing a transaction output
// spendable by wallet.  The output is added unspent, and is marked spent
// when a new transaction spending the output is inserted into the store.
//
// TODO(jrick): This should not be necessary.  Instead, pass the indexes
// that are known to contain credits when a transaction or merkleblock is
// inserted into the store.

// addCredit is an AddCredit helper that runs in an update transaction.  The
// bool return specifies whether the unspent output is newly added (true) or a
// duplicate (false).

// Rollback removes all blocks at height onwards, moving any transactions within
// each block to the unconfirmed pool.

func (s *Store) Rollback(managerAbe *waddrmgr.Manager, waddrmgr walletdb.ReadWriteBucket, wtxmgr walletdb.ReadWriteBucket, height int32) error {
	return s.rollback(managerAbe, waddrmgr, wtxmgr, height)
}
func (s *Store) unconfirmRelevantTx(ns walletdb.ReadWriteBucket, outpoint *wire.OutPointAbe, height int32) error {
	k := canonicalOutPointAbe(outpoint.TxHash, outpoint.Index)
	relevantTxs := existsRawReleventTxs(ns, k)
	offset := 0
	for offset <= len(relevantTxs) {
		relevantTxHash := relevantTxs[offset : offset+chainhash.HashSize]
		offset += chainhash.HashSize

		hasInvalid := false
		serializedTx := existsRawConfirmedTx(ns, relevantTxHash)
		if len(serializedTx) == 0 {
			serializedTx = existsRawInvalidTx(ns, relevantTxHash)
			if len(serializedTx) == 0 {
				log.Errorf("can not fetch relevant transaction %v", relevantTxHash)
				continue
			}
			hasInvalid = true
		}
		tx := new(TxRecord)
		err := tx.Deserialize(serializedTx)
		if err != nil {
			return err
		}
		// assert
		if !bytes.Equal(tx.Hash[:], relevantTxHash) {
			return fmt.Errorf("unmatched transaction %s in unconfirmed transaction bucket", tx.Hash)
		}

		if !hasInvalid {
			err = deleteRawConfirmedTx(ns, relevantTxHash)
			if err != nil {
				return err
			}
		} else {
			err = deleteRawInvalidTx(ns, relevantTxHash)
			if err != nil {
				return err
			}
		}

		err = putInvalidTx(ns, tx)
		if err != nil {
			return err
		}

		s.NotifyTransactionRollback(&TransactionInfo{
			TxHash: &tx.Hash,
			Height: height,
		})
		log.Infof("send unconfirmed transaction notification %s at height %d", tx.Hash, height)
	}
	return nil
}

func (s *Store) invalidRelevantTx(ns walletdb.ReadWriteBucket, outpoint *wire.OutPointAbe, height int32) error {
	k := canonicalOutPointAbe(outpoint.TxHash, outpoint.Index)
	relevantTxs := existsRawReleventTxs(ns, k)
	offset := 0
	for offset <= len(relevantTxs) {
		relevantTxHash := relevantTxs[offset : offset+chainhash.HashSize]
		offset += chainhash.HashSize

		hasConfirmed := false
		serializedTx := existsRawUnconfirmedTx(ns, relevantTxHash)
		if len(serializedTx) == 0 {
			serializedTx = existsRawConfirmedTx(ns, relevantTxHash)
			if len(serializedTx) == 0 {
				log.Errorf("can not fetch relevant transaction %v", relevantTxHash)
				continue
			}
			hasConfirmed = true
		}
		tx := new(TxRecord)
		err := tx.Deserialize(serializedTx)
		if err != nil {
			return err
		}
		// assert
		if !bytes.Equal(tx.Hash[:], relevantTxHash) {
			return fmt.Errorf("unmatched transaction %s in unconfirmed transaction bucket", tx.Hash)
		}

		if !hasConfirmed {
			err = deleteRawUnconfirmedTx(ns, relevantTxHash)
			if err != nil {
				return err
			}
		} else {
			err = deleteRawConfirmedTx(ns, relevantTxHash)
			if err != nil {
				return err
			}
		}

		err = putInvalidTx(ns, tx)
		if err != nil {
			return err
		}

		s.NotifyTransactionInvalid(&TransactionInfo{
			TxHash: &tx.Hash,
			Height: height,
		})
		log.Infof("send invalid transaction notification %s at height %d", tx.Hash, height)

	}
	return nil
}

// TODO(abe): we center with block not transaction, because we do not support single transaction
// TODO(abe): need to update the balance in the function.
// TODO(abe):this function need to be test
// we will delete the block after given height in database
func (s *Store) rollback(manager *waddrmgr.Manager, waddrmgrNs walletdb.ReadWriteBucket, wtxmgrNs walletdb.ReadWriteBucket, height int32) error {
	balance, err := fetchMinedBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpendableBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	immatureCBBal, err := fetchImmatureCoinbaseBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	immatureTRBal, err := fetchImmatureTransferBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	unconfirmedBal, err := fetchUnconfirmedBalance(wtxmgrNs)
	if err != nil {
		return err
	}

	autBalances, err := fetchAUTMinedBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	autSpendableBal, err := fetchAUTSpenableBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	autImmatureBal, err := fetchAUTImmatureTransferBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	autUnconfirmedBal, err := fetchAUTUnconfirmedBalance(wtxmgrNs)
	if err != nil {
		return err
	}

	autRootCoinNum, err := fetchAUTRootCoinNum(wtxmgrNs)
	if err != nil {
		return err
	}
	autImmatureRootCoinNum, err := fetchAUTImmatureRootCoinNum(wtxmgrNs)
	if err != nil {
		return err
	}
	autSpendableRootCoinNum, err := fetchAUTSpenableRootCoinNum(wtxmgrNs)
	if err != nil {
		return err
	}
	autUnconfirmedRootCoinNum, err := fetchAUTUnconfirmedRootCoinNum(wtxmgrNs)
	if err != nil {
		return err
	}

	keysWithHeight := make(map[int32][]byte)
	maxHeight := height
	// because we do not know whether the blockIterator works properly,
	// we just use as following:
	blockNum := int32(wire.GetBlockNumPerRingGroupByBlockHeight(height))
	err = wtxmgrNs.NestedReadBucket(bucketBlocks).ForEach(func(k []byte, v []byte) error {
		heightK := int32(byteOrder.Uint32(k[0:4]))
		if heightK >= height-blockNum {
			keysWithHeight[heightK] = k
			if maxHeight < heightK {
				maxHeight = heightK
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// for all block whose height is more than height
	for i := maxHeight; i > height; i-- {
		willDeleteRingHash := make(map[chainhash.Hash]struct{})

		// modify the ring hash of outputs in previous two blocks if the block is the special height
		blockNumOfRing := int32(wire.GetBlockNumPerRingGroupByBlockHeight(i))
		if i%blockNumOfRing == blockNumOfRing-1 {
			// previous blocks' outputs
			for j := int32(0); j < blockNumOfRing; j++ {
				blockHeight := i - j
				var blockHash *chainhash.Hash
				var key []byte
				if _, ok := keysWithHeight[blockHeight]; ok {
					blockHash, err = chainhash.NewHash(keysWithHeight[blockHeight][4:])
					if err != nil {
						return err
					}
					//  compare database data
					otherBlockHash, _ := manager.BlockHash(waddrmgrNs, blockHeight)
					if !otherBlockHash.IsEqual(blockHash) {
						log.Infof("err on database")
					}
					key = keysWithHeight[blockHeight]
				} else {
					blockHash, err = manager.BlockHash(waddrmgrNs, blockHeight)
					if err != nil {
						return err
					}
					key = make([]byte, 36)
					byteOrder.PutUint32(key, uint32(blockHeight))
					copy(key[4:], blockHash[:])
				}

				outpoints, err := fetchBlockOutput(wtxmgrNs, blockHeight, *blockHash)
				if outpoints == nil {
					continue
				}
				cbOutput, err := fetchImmatureCoinbaseOutput(wtxmgrNs, blockHeight, *blockHash)
				if err != nil {
					return err
				}
				trOutput := make(map[wire.OutPointAbe]*SpendableTXO, len(outpoints))
				for _, outpoint := range outpoints {
					// check in immature coinbase output -> immature coinbase output
					if cbOutput != nil {
						if utxo, ok := cbOutput[*outpoint]; ok {
							tmp, err := chainhash.NewHash(utxo.RingHash[:])
							if err != nil {
								return err
							}
							if _, ok := willDeleteRingHash[*tmp]; !ok {
								willDeleteRingHash[*tmp] = struct{}{}
							}
							utxo.RingHash = chainhash.ZeroHash
							utxo.RingSize = 0
							utxo.RingIndex = 0xFF
							continue
						}
					}
					// mature/spendbutunmined/spentandconfirmed output -> immature output
					// check in mature output
					if output, err := fetchSpendableTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output != nil {
						amt := abeutil.Amount(output.Amount)
						spendableBal -= amt
						immatureTRBal += amt
						log.Infof("(Rollback) (ABEL) Transfer txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): spendable -> immature",
							output.Version, output.TxOutput.TxHash, output.TxOutput.Index, blockHeight, blockHash, amt.ToABE(), output.IsPseudonymous())

						if output.IsAUTCoin() {
							autCoin, err := fetchRawAUTCoin(wtxmgrNs, output.TxOutput.TxHash, output.TxOutput.Index)
							if err != nil {
								return err
							}
							if autCoin.IsAUTRootCoin {
								autSpendableRootCoinNum[string(autCoin.AUTIdentifier)] -= 1
								autImmatureRootCoinNum[string(autCoin.AUTIdentifier)] += 1

								log.Infof("(Rollback) (AUT) root coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s): spendable -> immature",
									autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), blockHeight, blockHash)

							} else {
								autSpendableBal[string(autCoin.AUTIdentifier)] -= autCoin.AUTCoinValue
								autImmatureBal[string(autCoin.AUTIdentifier)] += autCoin.AUTCoinValue

								log.Infof("(Rollback) (AUT) coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s) with value %v: spendable -> immature",
									autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), blockHeight, blockHash, autCoin.AUTCoinValue)
							}
						}

						tmp, err := chainhash.NewHash(output.RingHash[:])
						if err != nil {
							return err
						}
						if _, ok := willDeleteRingHash[*tmp]; !ok {
							willDeleteRingHash[*tmp] = struct{}{}
						}

						k := canonicalOutPointAbe(outpoint.TxHash, outpoint.Index)
						output.RingHash = chainhash.ZeroHash
						output.RingIndex = 0xFF
						output.RingSize = 0
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, k)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteSpendableTXO(wtxmgrNs, k)
						if err != nil {
							return err
						}
						trOutput[*outpoint] = output
						continue
					}
					// check in unconfirmed output bucket
					if output, err := fetchUnconfirmedTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output != nil {
						amt := abeutil.Amount(output.Amount)
						unconfirmedBal -= amt
						immatureTRBal += amt
						log.Infof("(Rollback) (ABEL) Transfer txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): spent but unmined -> immature",
							output.Version, output.TxOutput.TxHash, output.TxOutput.Index, blockHeight, blockHash, amt.ToABE(), output.IsPseudonymous())

						if output.IsAUTCoin() {
							autCoin, err := fetchRawAUTCoin(wtxmgrNs, outpoint.TxHash, outpoint.Index)
							if err != nil {
								return err
							}
							if autCoin.IsAUTRootCoin {
								autUnconfirmedRootCoinNum[string(autCoin.AUTIdentifier)] -= 1
								autImmatureRootCoinNum[string(autCoin.AUTIdentifier)] += 1

								log.Infof("(Rollback) (AUT) root coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s): spent but unmined -> immature",
									autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), blockHeight, blockHash)

							} else {
								autUnconfirmedBal[string(autCoin.AUTIdentifier)] -= autCoin.AUTCoinValue
								autImmatureBal[string(autCoin.AUTIdentifier)] += autCoin.AUTCoinValue

								log.Infof("(Rollback) (AUT) coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s) with value %v: spent but unmined -> immature",
									autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), blockHeight, blockHash, autCoin.AUTCoinValue)
							}

							autCoin.Spent = false
							err = putRawAUTCoin(wtxmgrNs, outpoint.TxHash, outpoint.Index, autCoin)
							if err != nil {
								return err
							}
						}

						tmp, err := chainhash.NewHash(output.RingHash[:])
						if err != nil {
							return err
						}
						if _, ok := willDeleteRingHash[*tmp]; !ok {
							willDeleteRingHash[*tmp] = struct{}{}
						}

						k := canonicalOutPointAbe(outpoint.TxHash, outpoint.Index)
						output.RingHash = chainhash.ZeroHash
						output.RingIndex = 0xFF
						output.RingSize = 0
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, k)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteUnconfirmedTXO(wtxmgrNs, k)
						if err != nil {
							return err
						}

						trOutput[*outpoint] = &output.SpendableTXO
						continue
					}
					// check in unconfirmed output
					if output, err := fetchConfirmedTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output != nil {
						amt := abeutil.Amount(output.Amount)
						immatureTRBal += amt
						balance += amt
						log.Infof("(Rollback) (ABEL) Transfer txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): spent and minded -> immature",
							output.Version, output.TxOutput.TxHash, output.TxOutput.Index, blockHeight, blockHash, amt.ToABE(), output.IsPseudonymous())

						if output.IsAUTCoin() {
							autCoin, err := fetchRawAUTCoin(wtxmgrNs, outpoint.TxHash, outpoint.Index)
							if err != nil {
								return err
							}
							if autCoin.IsAUTRootCoin {
								autUnconfirmedRootCoinNum[string(autCoin.AUTIdentifier)] -= 1
								autImmatureRootCoinNum[string(autCoin.AUTIdentifier)] += 1

								log.Infof("(Rollback) (AUT) root coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s): spent and minded -> immature",
									autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), blockHeight, blockHash)

							} else {
								autUnconfirmedBal[string(autCoin.AUTIdentifier)] -= autCoin.AUTCoinValue
								autImmatureBal[string(autCoin.AUTIdentifier)] += autCoin.AUTCoinValue

								log.Infof("(Rollback) (AUT) coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s) with value %v: spent and minded -> immature",
									autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), blockHeight, blockHash, autCoin.AUTCoinValue)
							}

							autCoin.Spent = false
							err = putRawAUTCoin(wtxmgrNs, outpoint.TxHash, outpoint.Index, autCoin)
							if err != nil {
								return err
							}
						}

						tmp, err := chainhash.NewHash(output.RingHash[:])
						if err != nil {
							return err
						}
						if _, ok := willDeleteRingHash[*tmp]; !ok {
							willDeleteRingHash[*tmp] = struct{}{}
						}

						k := canonicalOutPointAbe(outpoint.TxHash, outpoint.Index)

						output.RingHash = chainhash.ZeroHash
						output.RingIndex = 0xFF
						output.RingSize = 0
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, k)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteConfirmedTXO(wtxmgrNs, k)
						if err != nil {
							return err
						}
						trOutput[*outpoint] = &output.SpendableTXO
					} else {
						// something error in database
						log.Errorf("rollback wrong in height %d: can not find outpoint %s:%d in spendable/unconfirmed/confirmed txo bucket", i, outpoint.TxHash, outpoint.Index)
					}
				}
				err = putImmatureCoinbaseOutput(wtxmgrNs, blockHeight, *blockHash, cbOutput)
				if err != nil {
					return err
				}
				err = putImmatureOutput(wtxmgrNs, blockHeight, *blockHash, trOutput)
				if err != nil {
					return err
				}
			}
		}
		//delete the utxoring and the ring
		for hash, _ := range willDeleteRingHash {
			err := deleteUTXORing(wtxmgrNs, hash[:])
			if err != nil {
				return fmt.Errorf("error in deleteUTXORing in rollbackAbe: %v", err)
			}
			err = deleteRingDetails(wtxmgrNs, hash[:]) //delete the ring detail when delete the utxo ring in rollback
			if err != nil {
				return fmt.Errorf("error in deleteRingDetail in rollbackAbe: %v", err)
			}
		}

		// fetch all output in current block, and delete it
		// When the block height hit the condition, the output would be in Immature Bucket base on above operation

		var blockHash *chainhash.Hash
		if _, ok := keysWithHeight[i]; ok {
			blockHash, err = chainhash.NewHash(keysWithHeight[i][4:])
			if err != nil {
				return err
			}
			//  compare database data
			otherblockHash, _ := manager.BlockHash(waddrmgrNs, i)
			if !otherblockHash.IsEqual(blockHash) {
				log.Infof("err on database")
			}
		} else {
			blockHash, err = manager.BlockHash(waddrmgrNs, i)
			if err != nil {
				return err
			}
		}
		coinbaseOutputs, err := fetchImmatureCoinbaseOutput(wtxmgrNs, i, *blockHash)
		if err == nil && coinbaseOutputs != nil {
			for _, unspentUTXO := range coinbaseOutputs {
				amt := abeutil.Amount(unspentUTXO.Amount)
				immatureCBBal -= amt
				balance -= amt
				log.Infof("(Rollback) (ABEL) Coinbase txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): immature -> null",
					unspentUTXO.Version, unspentUTXO.TxOutput.TxHash, unspentUTXO.TxOutput.Index, i, blockHash, amt.ToABE(), unspentUTXO.IsPseudonymous())

				// aut coin impossible in coinbase transaction
			}
			err = deleteImmatureCoinbaseOutput(wtxmgrNs, keysWithHeight[i])
			if err != nil {
				return fmt.Errorf("error in deleteImmatureCoinbaseOutput in rollback")
			}
		}
		transferOutputs, err := fetchImmatureOutput(wtxmgrNs, i, *blockHash)
		if err == nil && transferOutputs != nil {
			for outpointAbe, unspentUTXO := range transferOutputs {
				amt := abeutil.Amount(unspentUTXO.Amount)
				immatureTRBal -= amt
				balance -= amt
				log.Infof("(Rollback) (ABEL) Transfer txo (version %08x, hash %s, index %d)  in height %d (hash %s) with value %v (pseudonymous %t): immature -> null",
					unspentUTXO.Version, unspentUTXO.TxOutput.TxHash, unspentUTXO.TxOutput.Index, i, blockHash, amt.ToABE(), unspentUTXO.IsPseudonymous())
				// TODO(abe) 20220728 whether remove all transaction whose inputs contains this output or not?
				// when the output is removed from wallet.

				if unspentUTXO.IsAUTCoin() {
					k := canonicalOutPointAbe(outpointAbe.TxHash, outpointAbe.Index)
					autCoin, err := fetchRawAUTCoin(wtxmgrNs, unspentUTXO.TxOutput.TxHash, unspentUTXO.TxOutput.Index)
					if err != nil {
						return err
					}
					if autCoin.IsAUTRootCoin {
						autImmatureRootCoinNum[string(autCoin.AUTIdentifier)] -= 1
						autRootCoinNum[string(autCoin.AUTIdentifier)] -= 1

						log.Infof("(Rollback) (AUT) root coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s): immature -> null",
							autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), i, blockHash)

					} else {
						autImmatureBal[string(autCoin.AUTIdentifier)] -= autCoin.AUTCoinValue
						autBalances[string(autCoin.AUTIdentifier)] -= autCoin.AUTCoinValue

						log.Infof("(Rollback) (AUT) coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s) with value %v: immature -> null",
							autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), i, blockHash, autCoin.AUTCoinValue)
					}

					err = deleteRawAUTCoin(wtxmgrNs, k)
					if err != nil {
						return err
					}
				}
			}
			err = deleteImmatureOutput(wtxmgrNs, keysWithHeight[i])
			if err != nil {
				return fmt.Errorf("error in deleteImmatureOutput in rollback")
			}
		}

		// restore the input in block
		utxoRings, ss, err := fetchBlockInput(wtxmgrNs, keysWithHeight[i]) //there should be fetch the byte not the utxoRing
		for j := 0; j < len(utxoRings); j++ {
			u, err := fetchUTXORing(wtxmgrNs, utxoRings[j].RingHash[:])
			if err != nil {
				return err
			}
			if u == nil {
				// if the utxo ring do not exist in utxoring bucket, it means that the utxoring is deleted when processing this block
				// restore the outputs deleted when attaching this block
				for k := 0; k < len(utxoRings[j].IsMy); k++ {
					if utxoRings[j].IsMy[k] && !utxoRings[j].Spent[k] { // is my but not spend
						key := canonicalOutPointAbe(utxoRings[j].TxHashes[k], utxoRings[j].OutputIndexes[k])
						scoutput, err := fetchConfirmedTXO(wtxmgrNs, utxoRings[j].TxHashes[k], utxoRings[j].OutputIndexes[k])
						if err != nil {
							return err
						}
						err = putSpendableTXO(wtxmgrNs, &scoutput.SpendableTXO)
						if err != nil {
							return err
						}
						amt := abeutil.Amount(scoutput.Amount)
						spendableBal += amt
						balance += amt
						if scoutput.IsCoinbase() {
							log.Infof("(Rollback) (ABEL) Spent coinbase txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): -> spendable",
								scoutput.Version, scoutput.TxOutput.TxHash, scoutput.TxOutput.Index, i, blockHash, amt.ToABE(), scoutput.IsPseudonymous())
						} else {
							log.Infof("(Rollback) (ABEL) Spent transfer txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): -> spendable",
								scoutput.Version, scoutput.TxOutput.TxHash, scoutput.TxOutput.Index, i, blockHash, amt.ToABE(), scoutput.IsPseudonymous())

							if scoutput.IsAUTCoin() {
								autCoin, err := fetchRawAUTCoin(wtxmgrNs, scoutput.TxOutput.TxHash, scoutput.TxOutput.Index)
								if err != nil {
									return err
								}
								if autCoin.IsAUTRootCoin {
									autSpendableRootCoinNum[string(autCoin.AUTIdentifier)] += 1
									autRootCoinNum[string(autCoin.AUTIdentifier)] += 1

									log.Infof("(Rollback) (AUT) root coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s): -> spendable",
										autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), i, blockHash)

								} else {
									autSpendableBal[string(autCoin.AUTIdentifier)] += autCoin.AUTCoinValue
									autBalances[string(autCoin.AUTIdentifier)] += autCoin.AUTCoinValue

									log.Infof("(Rollback) (AUT) coin (hash %s, index %d) for AUT (identifer %s) in height %d (hash %s) with value %v: -> spendable",
										autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), i, blockHash, autCoin.AUTCoinValue)
								}

								autCoin.Spent = false
								err = putRawAUTCoin(wtxmgrNs, utxoRings[j].TxHashes[k], utxoRings[j].OutputIndexes[k], autCoin)
								if err != nil {
									return err
								}
							}
						}
						outpint := canonicalOutPointAbe(scoutput.TxOutput.TxHash, scoutput.TxOutput.Index)
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send unconfirmed notification to registered client
									err = putRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionRollback(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send unconfirmed transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send unconfirmed notification to registered client
									err = putRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionRollback(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send unconfirmed transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteConfirmedTXO(wtxmgrNs, key)
						if err != nil {
							return err
						}
					}
				}
			} else {
				// compare the delta and update the utxo ring entry
				for k := 0; k < len(ss[j]); k++ {
					for m, sn := range u.OriginSerialNumberes {
						if bytes.Equal(sn, ss[j][k]) && utxoRings[j].IsMy[m] && !utxoRings[j].Spent[m] {
							key := canonicalOutPointAbe(utxoRings[j].TxHashes[m], utxoRings[j].OutputIndexes[m])
							scoutput, err := fetchConfirmedTXO(wtxmgrNs, utxoRings[j].TxHashes[m], utxoRings[j].OutputIndexes[m])
							err = putSpendableTXO(wtxmgrNs, &scoutput.SpendableTXO)
							if err != nil {
								return err
							}
							amt := abeutil.Amount(scoutput.Amount)
							spendableBal += amt
							balance += amt
							if scoutput.IsCoinbase() {
								log.Infof("(Rollback) (ABEL) Coinbase txo (version %08x, hash %s, index %d) spent in height %d (hash %s) with value %v (pseudonymous %t): -> spendable",
									scoutput.Version, scoutput.TxOutput.TxHash, scoutput.TxOutput.Index, i, blockHash, amt.ToABE(), scoutput.IsPseudonymous())
							} else {
								log.Infof("(Rollback) (ABEL) Transfer txo (version %08x, hash %s, index %d) spent in height %d (hash %s) with value %v (pseudonymous %t): -> spendable",
									scoutput.Version, scoutput.TxOutput.TxHash, scoutput.TxOutput.Index, i, blockHash, amt.ToABE(), scoutput.IsPseudonymous())

								if scoutput.IsAUTCoin() {
									autCoin, err := fetchRawAUTCoin(wtxmgrNs, scoutput.TxOutput.TxHash, scoutput.TxOutput.Index)
									if err != nil {
										return err
									}
									if autCoin.IsAUTRootCoin {
										autSpendableRootCoinNum[string(autCoin.AUTIdentifier)] += 1
										autRootCoinNum[string(autCoin.AUTIdentifier)] += 1

										log.Infof("(Rollback) (AUT) root coin (hash %s, index %d) for AUT (identifer %s) in %d (hash %s): -> spendable",
											autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), i, blockHash)

									} else {
										autSpendableBal[string(autCoin.AUTIdentifier)] += autCoin.AUTCoinValue
										autBalances[string(autCoin.AUTIdentifier)] += autCoin.AUTCoinValue

										log.Infof("(Rollback) (AUT) coin (hash %s, index %d) for AUT (identifer %s) in %d (hash %s) with value %v: -> spendable",
											autCoin.TxOutput.TxHash, autCoin.TxOutput.Index, string(autCoin.AUTIdentifier), i, blockHash, autCoin.AUTCoinValue)
									}

									autCoin.Spent = false
									err = putRawAUTCoin(wtxmgrNs, utxoRings[j].TxHashes[m], utxoRings[j].OutputIndexes[m], autCoin)
									if err != nil {
										return err
									}
								}
							}
							outpint := canonicalOutPointAbe(scoutput.TxOutput.TxHash, scoutput.TxOutput.Index)
							// mark the all relevant transaction invalid
							relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
							if len(relevantTxs) != 0 {
								offset := 0
								for offset+chainhash.HashSize <= len(relevantTxs) {
									conflictTx := existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if len(conflictTx) != 0 {
										tx := new(TxRecord)
										err := tx.Deserialize(conflictTx)
										if err != nil {
											return err
										}
										// assert
										if !bytes.Equal(tx.Hash[:], relevantTxs[offset:offset+chainhash.HashSize]) {
											return fmt.Errorf("unmatched transaction %s in unconfirmed transaction bucket", tx.Hash)
										}

										err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
										if err != nil {
											return err
										}
										// TODO(202211) send unconfirmed notification to registered client
										err = putRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
										if err != nil {
											return err
										}
										txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
										s.NotifyTransactionRollback(&TransactionInfo{
											TxHash: txHash,
											Height: i,
										})
										log.Infof("send unconfirmed transaction notification %v at height %d", txHash, i)
									}
									conflictTx = existsRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if len(conflictTx) != 0 {
										tx := new(TxRecord)
										err := tx.Deserialize(conflictTx)
										if err != nil {
											return err
										}
										// assert
										if !bytes.Equal(tx.Hash[:], relevantTxs[offset:offset+chainhash.HashSize]) {
											return fmt.Errorf("unmatched transaction %s in unconfirmed transaction bucket", tx.Hash)
										}
										err = deleteRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
										if err != nil {
											return err
										}
										// TODO(202211) send unconfirmed notification to registered client
										err = putRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
										if err != nil {
											return err
										}
										txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
										s.NotifyTransactionRollback(&TransactionInfo{
											TxHash: txHash,
											Height: i,
										})
										log.Infof("send unconfirmed transaction notification %v at height %d", txHash, i)
									}
									offset += chainhash.HashSize
								}
							}
							err = deleteConfirmedTXO(wtxmgrNs, key)
							if err != nil {
								return err
							}
							break
						}
					}
				}
			}
			err = putUTXORing(wtxmgrNs, utxoRings[j].RingHash, utxoRings[j])
			if err != nil {
				return err
			}
		}
		//delete the block
		err = deleteRawBlockWithBlockHeight(wtxmgrNs, i)
		if err != nil {
			return fmt.Errorf("deleteRawBlockWithBlockHeight in rollback with err:%v", err)
		}

		disabledAUTPoints, err := fetchBlockDisabledAUTRootCoins(wtxmgrNs, keysWithHeight[i])
		if err != nil {
			return err
		}
		for _, point := range disabledAUTPoints {
			autRootCoin, err := restoreAUTCoin(wtxmgrNs, point.TxHash, point.Index)
			if err != nil {
				return err
			}

			autRootCoinNum[string(autRootCoin.AUTIdentifier)] += 1
			autSpendableRootCoinNum[string(autRootCoin.AUTIdentifier)] += 1

			log.Infof("(Rollback) (AUT) Restore my aut root coin (identifer %s, hash %s, index %d) disabled by re-registration",
				string(autRootCoin.AUTIdentifier), autRootCoin.TxOutput.TxHash, autRootCoin.TxOutput.Index)
		}
		err = deleteBlockDisabledAUTRootCoins(wtxmgrNs, keysWithHeight[i])
		if err != nil {
			return err
		}

		// immature coinbase outputs if exist
		maturity := int32(s.chainParams.CoinbaseMaturity)
		if i >= maturity && (i-maturity+1)%blockNum == 0 {
			for ii := int32(0); ii < blockNum; ii++ {
				key, outpoints, err := fetchBlockOutputWithHeight(wtxmgrNs, i-maturity-ii)
				if err != nil {
					return err
				}
				if key == nil || outpoints == nil {
					continue
				}
				currentBlockHash, err := chainhash.NewHash(key[4:36])
				if err != nil {
					return err
				}
				cbOutput := make(map[wire.OutPointAbe]*SpendableTXO, len(outpoints))
				for _, outpoint := range outpoints {
					// check in mature output
					if output, err := fetchSpendableTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output.IsCoinbase() {
						amt := abeutil.Amount(output.Amount)
						spendableBal -= amt
						immatureCBBal += amt
						log.Infof("(Rollback) (ABEL) Coinbase txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): spendable -> immature",
							output.Version, output.TxOutput.TxHash, output.TxOutput.Index, i-maturity-ii, currentBlockHash, amt.ToABE(), output.IsPseudonymous())
						outpint := canonicalOutPointAbe(output.TxOutput.TxHash, output.TxOutput.Index)
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteSpendableTXO(wtxmgrNs, canonicalOutPointAbe(outpoint.TxHash, outpoint.Index))
						if err != nil {
							return err
						}
						cbOutput[*outpoint] = output
						continue
					}
					// check in spend but unmined output
					if output, err := fetchUnconfirmedTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output.IsCoinbase() {
						amt := abeutil.Amount(output.Amount)
						unconfirmedBal -= amt
						immatureCBBal += amt
						log.Infof("(Rollback) (ABEL) Coinbase txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): spent but unmined -> immature",
							output.Version, output.TxOutput.TxHash, output.TxOutput.Index, i-maturity-ii, currentBlockHash, amt.ToABE(), output.IsPseudonymous())

						outpint := canonicalOutPointAbe(output.TxOutput.TxHash, output.TxOutput.Index)
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteUnconfirmedTXO(wtxmgrNs, canonicalOutPointAbe(outpoint.TxHash, outpoint.Index))
						if err != nil {
							return err
						}
						cbOutput[*outpoint] = &SpendableTXO{
							Version:        output.Version,
							Height:         output.Height,
							TxOutput:       output.TxOutput,
							PackedFlag:     output.PackedFlag,
							Amount:         output.Amount,
							RingIndex:      output.RingIndex,
							GenerationTime: output.GenerationTime,
							RingHash:       output.RingHash,
							RingSize:       output.RingSize,
						}
						continue
					}
					// check in spent and mined output
					if output, err := fetchConfirmedTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output.IsCoinbase() {
						amt := abeutil.Amount(output.Amount)
						unconfirmedBal += amt
						balance += amt
						log.Infof("(Rollback) (ABEL) Coinbase txo (version %08x, hash %s, index %d) in height %d (hash %s) with value %v (pseudonymous %t): spent -> unconfirmed",
							output.Version, output.TxOutput.TxHash, output.TxOutput.Index, i-maturity-ii, currentBlockHash, amt.ToABE(), output.IsPseudonymous())
						outpint := canonicalOutPointAbe(output.TxOutput.TxHash, output.TxOutput.Index)
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteConfirmedTXO(wtxmgrNs, canonicalOutPointAbe(outpoint.TxHash, outpoint.Index))
						if err != nil {
							return err
						}
						cbOutput[*outpoint] = &SpendableTXO{
							Version:        output.Version,
							Height:         output.Height,
							TxOutput:       output.TxOutput,
							PackedFlag:     output.PackedFlag,
							Amount:         output.Amount,
							RingIndex:      output.RingIndex,
							GenerationTime: output.GenerationTime,
							RingHash:       output.RingHash,
							RingSize:       output.RingSize,
						}
						continue
					}
				}
				err = putImmatureCoinbaseOutput(wtxmgrNs, i, *blockHash, cbOutput)
				if err != nil {
					return err
				}
			}
		}
	}

	// update the balances
	err = putSpendableBalance(wtxmgrNs, spendableBal)
	if err != nil {
		return err
	}
	err = putImmatureCoinbaseBalance(wtxmgrNs, immatureCBBal)
	if err != nil {
		return err
	}
	err = putImmatureTransferBalance(wtxmgrNs, immatureTRBal)
	if err != nil {
		return err
	}
	err = putUnconfirmedBalance(wtxmgrNs, unconfirmedBal)
	if err != nil {
		return err
	}
	err = putMinedBalance(wtxmgrNs, balance)
	if err != nil {
		return err
	}

	err = putAUTImmatureRootCoinNum(wtxmgrNs, autImmatureRootCoinNum)
	if err != nil {
		return err
	}
	err = putAUTSpenableRootCoinNum(wtxmgrNs, autSpendableRootCoinNum)
	if err != nil {
		return err
	}
	err = putAUTUnconfirmedRootCoinNum(wtxmgrNs, autUnconfirmedRootCoinNum)
	if err != nil {
		return err
	}
	err = putAUTRootCoinNum(wtxmgrNs, autRootCoinNum)
	if err != nil {
		return err
	}

	err = putAUTImmatureTransferBalance(wtxmgrNs, autImmatureBal)
	if err != nil {
		return err
	}
	err = putAUTSpenableBalance(wtxmgrNs, autSpendableBal)
	if err != nil {
		return err
	}
	err = putAUTUnconfirmedBalance(wtxmgrNs, autUnconfirmedBal)
	if err != nil {
		return err
	}
	err = putAUTMinedBalance(wtxmgrNs, autBalances)
	if err != nil {
		return err
	}

	return nil
}

// UnspentOutputs returns all unspent received transaction outputs.
// The order is undefined.
func (s *Store) UnmaturedOutputs(ns walletdb.ReadBucket) ([]SpendableTXO, error) {
	unmatureds := make([]SpendableTXO, 0)

	// block height block hash -> []Unspent
	err := ns.NestedReadBucket(bucketImmaturedCoinbaseOutput).ForEach(func(_, v []byte) error {
		op, err := deserializedImmatureCoinbaseOutput(v)
		if err != nil {
			return err
		}
		for _, ust := range op {
			unmatureds = append(unmatureds, *ust)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}
	err = ns.NestedReadBucket(bucketImmaturedOutput).ForEach(func(k, v []byte) error {
		op, err := deserializedImmatureOutput(v)
		if err != nil {
			return err
		}
		for _, ust := range op {
			unmatureds = append(unmatureds, *ust)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	//	todo(ABE): For ABE, only the Txos confirmed by blocks and contained in some ring are spentable.
	return unmatureds, nil
}
func (s *Store) SpentAndMinedOutputs(ns walletdb.ReadBucket) ([]ConfirmedTXO, error) {
	samtxos := make([]ConfirmedTXO, 0)

	var op wire.OutPointAbe
	//var block BlockAbe
	err := ns.NestedReadBucket(bucketSpentConfirmed).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}

		sct := new(ConfirmedTXO)
		err = sct.Deserialize(&op, v)
		if err != nil {
			return err
		}
		samtxos = append(samtxos, *sct)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	//	todo(ABE): For ABE, only the Txos confirmed by blocks and contained in some ring are spentable.
	return samtxos, nil
}
func (s *Store) SpentButUnminedOutputs(ns walletdb.ReadBucket) ([]UnconfirmedTXO, error) {
	sbutxos := make([]UnconfirmedTXO, 0)

	var op wire.OutPointAbe
	//var block BlockAbe
	err := ns.NestedReadBucket(bucketSpentButUnmined).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}
		sbu := new(UnconfirmedTXO)
		err = sbu.Deserialize(&op, v)
		if err != nil {
			return err
		}
		sbutxos = append(sbutxos, *sbu)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	//	todo(ABE): For ABE, only the Txos confirmed by blocks and contained in some ring are spentable.
	return sbutxos, nil
}
func (s *Store) UnspentOutputs(ns walletdb.ReadBucket) ([]SpendableTXO, error) {
	unspent := make([]SpendableTXO, 0)

	var op wire.OutPointAbe
	//var block BlockAbe
	err := ns.NestedReadBucket(bucketMaturedOutput).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}
		ust := new(SpendableTXO)
		err = ust.Deserialize(&op, v)
		if err != nil {
			return err
		}
		unspent = append(unspent, *ust)
		return nil
		//	todo(ABE): what happens when a TXO is spent and confirmed by a block?
		//if existsRawUnminedInput(ns, k) != nil {
		//	// Output is spent by an unmined transaction.
		//	// Skip this k/v pair.
		//	return nil
		//}

		//err = readCanonicalBlock(k, &block)
		//if err != nil {
		//	return err
		//}

		//blockTime, err := fetchBlockTime(ns, block.Height)
		//if err != nil {
		//	return err
		//}
		// TODO(jrick): reading the entire transaction should
		// be avoidable.  Creating the credit only requires the
		// output amount and pkScript.
		//	todo(ABE): Agreed on that Creating the credit only requires the output amount and pkScript.
		//	todo(ABE): The wallet database should be TXO-centric.
		//rec, err := fetchTxRecord(ns, &op.TxHash, &block)
		//if err != nil {
		//	return fmt.Errorf("unable to retrieve transaction %v: "+
		//		"%v", op.Hash, err)
		//}
		//txOut := rec.MsgTx.TxOut[op.Index]
		//ust := SpendableTXO{
		//	Height:         -1,
		//	TxOutput:       op,
		//	FromCoinBase:   false,
		//	Amount:         0,
		//	GenerationTime: time.Time{},
		//	RingHash:       chainhash.Hash{},
		//}
		//TODO(abe): provided a function to deserialize the unspent output
		//offset := 0
		//ust.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
		//offset += 4
		//t := v[offset]
		//offset += 1
		//if t == 0 {
		//	ust.FromCoinBase = false
		//} else {
		//	ust.FromCoinBase = true
		//}
		//ust.Amount = int64(byteOrder.Uint64(v[offset : offset+8]))
		//offset += 8
		//ust.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
		//offset += 8
		//copy(ust.RingHash[:], v[offset:offset+32])
		//offset += 32
		//if !ust.RingHash.IsEqual(&chainhash.ZeroHash) {
		//	unspent = append(unspent, ust)
		//}
		//return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	//	todo(ABE): For ABE, only the Txos confirmed by blocks and contained in some ring are spentable.
	return unspent, nil
}

func (s *Store) UnspentOutputsAUT(ns walletdb.ReadBucket, autIdentifier []byte, rootCoinOnly bool) ([]*AUTCoin, []*SpendableTXO, error) {
	autCoins := make([]*AUTCoin, 0)

	var op wire.OutPointAbe
	autEntryBucket := ns.NestedReadBucket(bucketAUTPoint)

	if autEntryBucket == nil {
		return nil, nil, errors.New("non-exist bucket for aut point")
	}
	err := autEntryBucket.ForEach(func(k, v []byte) error {
		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}
		ust := new(AUTCoin)
		err = ust.Deserialize(&op, v)
		if err != nil {
			return err
		}
		if rootCoinOnly && !ust.IsAUTRootCoin {
			return nil
		}
		if len(autIdentifier) != 0 && !bytes.Equal(ust.AUTIdentifier, autIdentifier) {
			return nil
		}
		autCoins = append(autCoins, ust)

		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, nil, err
		}
		str := "failed iterating aut point bucket"
		return nil, nil, storeError(ErrDatabase, str, err)
	}

	utxos := make([]*SpendableTXO, len(autCoins))
	for i, coin := range autCoins {
		txo, err := fetchSpendableTXO(ns, coin.TxOutput.TxHash, coin.TxOutput.Index)
		if err != nil {
			return nil, nil, err
		}
		utxos[i] = txo
	}
	return autCoins, utxos, nil
}
func (s *Store) UnspentOutputsCTAUT(ns walletdb.ReadBucket, autIdentifier []byte, isRootCoin bool) ([]*CTAUTCoin, []*SpendableTXO, error) {
	tokens := make([]*CTAUTCoin, 0)

	var op wire.OutPointAbe
	ctautEntryBucket := ns.NestedReadBucket(bucketCTAUTPoint)

	if ctautEntryBucket == nil {
		return nil, nil, errors.New("non-exist bucket for ct-aut point")
	}
	err := ctautEntryBucket.ForEach(func(k, v []byte) error {
		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}
		ust := new(CTAUTCoin)
		err = ust.Deserialize(&op, v)
		if err != nil {
			return err
		}
		if isRootCoin && !ust.IsAUTRootCoin {
			return nil
		}
		if !isRootCoin && ust.IsAUTRootCoin {
			return nil
		}
		if len(autIdentifier) != 0 && !bytes.Equal(ust.AUTIdentifier, autIdentifier) {
			return nil
		}
		tokens = append(tokens, ust)

		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, nil, err
		}
		str := "failed iterating aut point bucket"
		return nil, nil, storeError(ErrDatabase, str, err)
	}

	utxos := make([]*SpendableTXO, len(tokens))
	for i, coin := range tokens {
		txo, err := fetchSpendableTXO(ns, coin.TxOutput.TxHash, coin.TxOutput.Index)
		if err != nil {
			return nil, nil, err
		}
		utxos[i] = txo
	}
	return tokens, utxos, nil
}

func (s *Store) AddressAUTCoins(ns walletdb.ReadBucket, autIdentifier []byte, addrKey []byte) ([]*AUTCoin, []*SpendableTXO, []*UnconfirmedTXO, error) {
	autCoins := make([]*AUTCoin, 0)

	var op wire.OutPointAbe
	autEntryBucket := ns.NestedReadBucket(bucketAUTPoint)

	if autEntryBucket == nil {
		return nil, nil, nil, errors.New("non-exist bucket for aut point")
	}
	err := autEntryBucket.ForEach(func(k, v []byte) error {
		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}
		ust := new(AUTCoin)
		err = ust.Deserialize(&op, v)
		if err != nil {
			return err
		}

		if len(autIdentifier) != 0 && !bytes.Equal(ust.AUTIdentifier, autIdentifier) {
			return nil
		}
		if !bytes.Equal(ust.AddrKey, addrKey) {
			return nil
		}

		autCoins = append(autCoins, ust)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, nil, nil, err
		}
		str := "failed iterating aut point bucket"
		return nil, nil, nil, storeError(ErrDatabase, str, err)
	}

	utxos := make([]*SpendableTXO, len(autCoins))
	unconfirmedTxos := make([]*UnconfirmedTXO, len(autCoins))
	for i, coin := range autCoins {
		txo, err := fetchSpendableTXO(ns, coin.TxOutput.TxHash, coin.TxOutput.Index)
		if err != nil {
			return nil, nil, nil, err
		}
		if txo == nil {
			unconfirmedTxos[i], err = fetchUnconfirmedTXO(ns, coin.TxOutput.TxHash, coin.TxOutput.Index)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		utxos[i] = txo
	}
	return autCoins, utxos, unconfirmedTxos, nil
}

// Balance returns the spendable wallet balance (total value of all unspent
// transaction outputs) given a minimum of minConf confirmations, calculated
// at a current chain height of curHeight.  Coinbase outputs are only included
// in the balance if maturity has been reached.
//
// Balance may return unexpected results if syncHeight is lower than the block
// height of the most recent mined transaction in the store.

func (s *Store) Balance(ns walletdb.ReadBucket, minConf int32, syncHeight int32) ([]abeutil.Amount, error) {
	allBal, err := fetchMinedBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	spendableBal, err := fetchSpendableBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	immatureCBBal, err := fetchImmatureCoinbaseBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	immatureTRBal, err := fetchImmatureTransferBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	unconfirmdBal, err := fetchUnconfirmedBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	return []abeutil.Amount{allBal, spendableBal, immatureCBBal, immatureTRBal, unconfirmdBal}, nil
}

func (s *Store) AUTBalance(ns walletdb.ReadBucket, minConf int32, syncHeight int32) ([]map[string]uint64, error) {
	autBalances, err := fetchAUTMinedBalance(ns)
	if err != nil {
		return nil, err
	}
	autSpendableBal, err := fetchAUTSpenableBalance(ns)
	if err != nil {
		return nil, err
	}
	autImmatureTRBal, err := fetchAUTImmatureTransferBalance(ns)
	if err != nil {
		return nil, err
	}
	autUnconfirmedBal, err := fetchAUTUnconfirmedBalance(ns)
	if err != nil {
		return nil, err
	}
	return []map[string]uint64{autBalances, autSpendableBal, autImmatureTRBal, autUnconfirmedBal}, nil
}
func (s *Store) AUTRootCoinNum(ns walletdb.ReadBucket, minConf int32, syncHeight int32) ([]map[string]uint64, error) {
	autRootCoinNum, err := fetchAUTRootCoinNum(ns)
	if err != nil {
		return nil, err
	}
	autImmatureRootCoinNum, err := fetchAUTImmatureRootCoinNum(ns)
	if err != nil {
		return nil, err
	}
	autSpendableRootCoinNum, err := fetchAUTSpenableRootCoinNum(ns)
	if err != nil {
		return nil, err
	}
	autUnconfirmedRootCoinNum, err := fetchAUTUnconfirmedRootCoinNum(ns)
	if err != nil {
		return nil, err
	}

	return []map[string]uint64{autRootCoinNum, autImmatureRootCoinNum, autSpendableRootCoinNum, autUnconfirmedRootCoinNum}, nil
}

// PutTxLabel validates transaction labels and writes them to disk if they
// are non-zero and within the label length limit. The entry is keyed by the
// transaction hash:
// [0:32] Transaction hash (32 bytes)
//
// The label itself is written to disk in length value format:
// [0:2] Label length
// [2: +len] Label
func (s *Store) PutTxLabel(ns walletdb.ReadWriteBucket, txid chainhash.Hash,
	label string) error {

	if len(label) == 0 {
		return ErrEmptyLabel
	}

	if len(label) > TxLabelLimit {
		return ErrLabelTooLong
	}

	labelBucket, err := ns.CreateBucketIfNotExists(bucketTxLabels)
	if err != nil {
		return err
	}

	return PutTxLabel(labelBucket, txid, label)
}

func (s *Store) PutRequestHashAndTxHash(ns walletdb.ReadWriteBucket, requestHash string, txHash string) error {
	requestBucket, err := ns.CreateBucketIfNotExists(bucketRequestRecord)
	if err != nil {
		return err
	}

	return requestBucket.Put([]byte(requestHash), []byte(txHash))
}
func (s *Store) GetTxHashRequestHash(ns walletdb.ReadBucket, requestHash string) (*chainhash.Hash, error) {
	requestBucket := ns.NestedReadBucket(bucketRequestRecord)
	// when the bucket is nil, it means that there no content
	if requestBucket == nil {
		return nil, errors.New("request bucket is empty")
	}
	txHashStrBytes := requestBucket.Get([]byte(requestHash))
	if len(txHashStrBytes) == 0 {
		return nil, errors.New("not exist")
	}
	return chainhash.NewHashFromStr(string(txHashStrBytes))
}

// PutTxLabel writes a label for a tx to the bucket provided. Note that it does
// not perform any validation on the label provided, or check whether there is
// an existing label for the txid.
func PutTxLabel(labelBucket walletdb.ReadWriteBucket, txid chainhash.Hash,
	label string) error {

	// We expect the label length to be limited on creation, so we can
	// store the label's length as a uint16.
	labelLen := uint16(len(label))

	var buf bytes.Buffer

	var b [2]byte
	binary.BigEndian.PutUint16(b[:], labelLen)
	if _, err := buf.Write(b[:]); err != nil {
		return err
	}

	if _, err := buf.WriteString(label); err != nil {
		return err
	}

	return labelBucket.Put(txid[:], buf.Bytes())
}

// FetchTxLabel reads a transaction label from the tx labels bucket. If a label
// with 0 length was written, we return an error, since this is unexpected.
func FetchTxLabel(ns walletdb.ReadBucket, txid chainhash.Hash) (string, error) {
	labelBucket := ns.NestedReadBucket(bucketTxLabels)
	if labelBucket == nil {
		return "", ErrNoLabelBucket
	}

	v := labelBucket.Get(txid[:])
	if v == nil {
		return "", ErrTxLabelNotFound
	}

	return DeserializeLabel(v)
}

// DeserializeLabel reads a deserializes a length-value encoded label from the
// byte array provided.
func DeserializeLabel(v []byte) (string, error) {
	// If the label is empty, return an error.
	length := binary.BigEndian.Uint16(v[0:2])
	if length == 0 {
		return "", ErrEmptyLabel
	}

	// Read the remainder of the bytes into a label string.
	label := string(v[2:])
	return label, nil
}

// isKnownOutput returns whether the output is known to the transaction store
// either as confirmed or unconfirmed.
func isKnownOutput(ns walletdb.ReadWriteBucket, op wire.OutPointAbe) bool {
	// TODO match to abe
	// (1) Check the unmine
	// (2) Check the matured
	//k := canonicalOutPoint(&op.Hash, op.Index)
	//if existsRawUnminedCredit(ns, k) != nil {
	//	return true
	//}
	//if existsRawUnspent(ns, k) != nil {
	//	return true
	//}
	return false
}

// LockOutput locks an output to the given ID, preventing it from being
// available for coin selection. The absolute time of the lock's expiration is
// returned. The expiration of the lock can be extended by successive
// invocations of this call.
//
// Outputs can be unlocked before their expiration through `UnlockOutput`.
// Otherwise, they are unlocked lazily through calls which iterate through all
// known outputs, e.g., `Balance`, `UnspentOutputs`.
//
// If the output is not known, ErrUnknownOutput is returned. If the output has
// already been locked to a different ID, then ErrOutputAlreadyLocked is
// returned.
func (s *Store) LockOutput(ns walletdb.ReadWriteBucket, id LockID,
	op wire.OutPointAbe) (time.Time, error) {

	// Make sure the output is known.
	if !isKnownOutput(ns, op) {
		return time.Time{}, ErrUnknownOutput
	}

	// Make sure the output hasn't already been locked to some other ID.
	lockedID, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
	if isLocked && lockedID != id {
		return time.Time{}, ErrOutputAlreadyLocked
	}

	expiry := s.clock.Now().Add(DefaultLockDuration)
	if err := lockOutput(ns, id, op, expiry); err != nil {
		return time.Time{}, err
	}

	return expiry, nil
}

// UnlockOutput unlocks an output, allowing it to be available for coin
// selection if it remains unspent. The ID should match the one used to
// originally lock the output.
func (s *Store) UnlockOutput(ns walletdb.ReadWriteBucket, id LockID,
	op wire.OutPointAbe) error {

	// Make sure the output is known.
	if !isKnownOutput(ns, op) {
		return ErrUnknownOutput
	}

	// If the output has already been unlocked, we can return now.
	lockedID, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
	if !isLocked {
		return nil
	}

	// Make sure the output was locked to the same ID.
	if lockedID != id {
		return ErrOutputUnlockNotAllowed
	}

	return unlockOutput(ns, op)
}

// DeleteExpiredLockedOutputs iterates through all existing locked outputs and
// deletes those which have already expired.
func (s *Store) DeleteExpiredLockedOutputs(ns walletdb.ReadWriteBucket) error {
	// Collect all expired output locks first to remove them later on. This
	// is necessary as deleting while iterating would invalidate the
	// iterator.
	var expiredOutputs []wire.OutPointAbe
	err := forEachLockedOutput(
		ns, func(op wire.OutPointAbe, _ LockID, expiration time.Time) {
			if !s.clock.Now().Before(expiration) {
				expiredOutputs = append(expiredOutputs, op)
			}
		},
	)
	if err != nil {
		return err
	}

	for _, op := range expiredOutputs {
		if err := unlockOutput(ns, op); err != nil {
			return err
		}
	}

	return nil
}
