package wtxmgr

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewalletmlp/walletdb"
)

func fetchCTAUTRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootCTAUTRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}
	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putCTAUTRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootCTAUTRootCoinNum, v)
	if err != nil {
		str := "failed to put aut balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchCTAUTMinedBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootCTAUTBalance)

	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putCTAUTMinedBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootCTAUTBalance, v)
	if err != nil {
		str := "failed to put aut balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchCTAUTSpenableBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootCTAUTSpendableBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut spendable balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putCTAUTSpenableBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootCTAUTSpendableBalance, v)
	if err != nil {
		str := "failed to put aut spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchCTAUTSpenableRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootCTAUTSpendableRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut spendable balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putCTAUTSpenableRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootCTAUTSpendableRootCoinNum, v)
	if err != nil {
		str := "failed to put aut spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchCTAUTImmatureRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootCTAUTImmatureRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut immature balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putCTAUTImmatureRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootCTAUTImmatureRootCoinNum, v)
	if err != nil {
		str := "failed to put aut immature balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchCTAUTImmatureTransferBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootCTAUTImmatureTransferBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut immature balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putCTAUTImmatureTransferBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootCTAUTImmatureTransferBalance, v)
	if err != nil {
		str := "failed to put aut immature balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchCTAUTUnconfirmedRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootCTAUTUnconfirmedRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut unconfirmed balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putCTAUTUnconfirmedRootCoinNum(ns walletdb.ReadWriteBucket, nums map[string]uint64) error {
	v, _ := json.Marshal(nums)
	err := ns.Put(rootCTAUTUnconfirmedRootCoinNum, v)
	if err != nil {
		str := "failed to put aut unconfirmed balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchCTAUTUnconfirmedBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootCTAUTUnconfirmedBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut unconfirmed balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putCTAUTUnconfirmedBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootCTAUTUnconfirmedBalance, v)
	if err != nil {
		str := "failed to put aut unconfirmed balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func putRawCTAUTCoin(ns walletdb.ReadWriteBucket, txHash chainhash.Hash, index uint8, coin *CTAUTCoin) error {
	k := canonicalOutPointAbe(txHash, index)
	v, err := coin.Serialized()
	if err != nil {
		return err
	}

	autPointBucket := ns.NestedReadWriteBucket(bucketCTAUTPoint)
	err = autPointBucket.Put(k, v)
	if err != nil {
		str := "failed to put aut entry"
		return storeError(ErrDatabase, str, err)
	}

	autCoin, err := fetchRawCTAUTCoin(ns, txHash, index)
	if err != nil {
		panic("unmatched CTAUTCoin serialized/deserialized")
	}
	if !reflect.DeepEqual(autCoin, coin) {
		log.Errorf("unmatched CTAUTCoin serialized/deserialized")
	}
	return nil
}

func fetchRawCTAUTCoin(ns walletdb.ReadBucket, txHash chainhash.Hash, index uint8) (*CTAUTCoin, error) {
	k := canonicalOutPointAbe(txHash, index)
	v := ns.NestedReadBucket(bucketCTAUTPoint).Get(k)
	if len(v) == 0 {
		str := "failed to fetch aut coin"
		return nil, storeError(ErrDatabase, str, fmt.Errorf("non-exst aut coin"))
	}

	autCoin := new(CTAUTCoin)
	err := autCoin.Deserialize(&wire.OutPointAbe{
		TxHash: txHash,
		Index:  index,
	}, v)
	if err != nil {
		str := "failed to deserialize the aut coin"
		return nil, storeError(ErrDatabase, str, err)
	}

	return autCoin, err
}

func existsRawCTAUTCoin(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketCTAUTPoint).Get(k)
}

func deleteRawCTAUTCoin(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketCTAUTPoint).Delete(k)
	if err != nil {
		str := "failed to delete aut coin"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func valueBlockDisabledCTAUTRootCoins(outpoints []*wire.OutPointAbe) []byte {
	res := make([]byte, 8+len(outpoints)*(chainhash.HashSize+1))
	byteOrder.PutUint32(res[0:4], uint32(8+len(outpoints)*(chainhash.HashSize+1)))
	byteOrder.PutUint32(res[4:8], uint32(len(outpoints)))
	offset := 8
	// total size of outpoints
	for _, outpoint := range outpoints {
		copy(res[offset:offset+chainhash.HashSize], outpoint.TxHash[:])
		offset += chainhash.HashSize
		res[offset] = outpoint.Index
		offset += 1
	}
	return res
}
func putBlockDisabledCTAUTRootCoins(ns walletdb.ReadWriteBucket, blockHeight int32, blockHash chainhash.Hash, outpoints []*wire.OutPointAbe) error {
	k := canonicalBlock(blockHeight, blockHash)
	v := valueBlockDisabledCTAUTRootCoins(outpoints)

	err := ns.NestedReadWriteBucket(bucketBlockDisabledCTAUTPoint).Put(k, v)
	if err != nil {
		str := "failed to put disable aut points"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchBlockDisabledCTAUTRootCoins(ns walletdb.ReadWriteBucket, k []byte) ([]*wire.OutPointAbe, error) {
	v := ns.NestedReadBucket(bucketBlockDisabledCTAUTPoint).Get(k)
	if len(v) == 0 {
		return nil, nil
	}
	_ = byteOrder.Uint32(v[0:4])
	outpointNum := int(byteOrder.Uint32(v[4:8]))
	offset := 8
	outpoints := make([]*wire.OutPointAbe, outpointNum)
	for i := 0; i < outpointNum; i++ {
		outpoints[i] = new(wire.OutPointAbe)
		copy(outpoints[i].TxHash[:], v[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize
		outpoints[i].Index = v[offset]
		offset += 1
	}
	return outpoints, nil
}
func deleteBlockDisabledCTAUTRootCoins(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockDisabledCTAUTPoint).Delete(k)
	if err != nil {
		str := "failed to delete block input"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// bucketCTAUTEntry:[autName -> [outpoint->aut coins]
func spendCTAUTCoin(ns walletdb.ReadWriteBucket, txHash chainhash.Hash, index uint8) (*CTAUTCoin, bool, error) {
	token, err := fetchRawCTAUTCoin(ns, txHash, index)
	if err != nil {
		return nil, false, err
	}

	// record the status of aut coin to distinguish that is consumed or just disabled
	spent := token.Spent
	token.Spent = true

	err = putRawCTAUTCoin(ns, txHash, index, token)
	if err != nil {
		str := "failed to spent aut coin"
		return nil, false, storeError(ErrDatabase, str, err)
	}

	return token, spent, nil
}

func restoreCTAUTCoin(ns walletdb.ReadWriteBucket, txHash chainhash.Hash, index uint8) (*CTAUTCoin, error) {
	autCoin, err := fetchRawCTAUTCoin(ns, txHash, index)
	if err != nil {
		return nil, err
	}

	autCoin.Spent = false

	err = putRawCTAUTCoin(ns, txHash, index, autCoin)
	if err != nil {
		str := "failed to spent aut coin"
		return nil, storeError(ErrDatabase, str, err)
	}

	return autCoin, nil
}
