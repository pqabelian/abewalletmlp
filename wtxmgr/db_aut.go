package wtxmgr

import (
	"encoding/json"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewalletmlp/walletdb"
	"reflect"
)

func fetchAUTRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}
	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTRootCoinNum, v)
	if err != nil {
		str := "failed to put aut balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchAUTMinedBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTBalance)

	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTMinedBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTBalance, v)
	if err != nil {
		str := "failed to put aut balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTSpenableBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTSpendableBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut spendable balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTSpenableBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTSpendableBalance, v)
	if err != nil {
		str := "failed to put aut spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTSpenableRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTSpendableRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut spendable balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTSpenableRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTSpendableRootCoinNum, v)
	if err != nil {
		str := "failed to put aut spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTImmatureRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTImmatureRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut immature balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTImmatureRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTImmatureRootCoinNum, v)
	if err != nil {
		str := "failed to put aut immature balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTImmatureTransferBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTImmatureTransferBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut immature balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTImmatureTransferBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTImmatureTransferBalance, v)
	if err != nil {
		str := "failed to put aut immature balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTUnconfirmedRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTUnconfirmedRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut unconfirmed balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTUnconfirmedRootCoinNum(ns walletdb.ReadWriteBucket, nums map[string]uint64) error {
	v, _ := json.Marshal(nums)
	err := ns.Put(rootAUTUnconfirmedRootCoinNum, v)
	if err != nil {
		str := "failed to put aut unconfirmed balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchAUTUnconfirmedBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTUnconfirmedBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut unconfirmed balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTUnconfirmedBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTUnconfirmedBalance, v)
	if err != nil {
		str := "failed to put aut unconfirmed balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func putRawAUTCoin(ns walletdb.ReadWriteBucket, txHash chainhash.Hash, index uint8, coin *AUTCoin) error {
	k := canonicalOutPointAbe(txHash, index)
	v, err := coin.Serialized()
	if err != nil {
		return err
	}

	autPointBucket := ns.NestedReadWriteBucket(bucketAUTPoint)
	err = autPointBucket.Put(k, v)
	if err != nil {
		str := "failed to put aut entry"
		return storeError(ErrDatabase, str, err)
	}

	autCoin, err := fetchRawAUTCoin(ns, txHash, index)
	if err != nil {
		panic("unmatched AUTCoin serialized/deserialized")
	}
	if !reflect.DeepEqual(autCoin, coin) {
		panic("unmatched AUTCoin serialized/deserialized")
	}
	return nil
}

func fetchRawAUTCoin(ns walletdb.ReadBucket, txHash chainhash.Hash, index uint8) (*AUTCoin, error) {
	k := canonicalOutPointAbe(txHash, index)
	v := ns.NestedReadBucket(bucketAUTPoint).Get(k)
	if len(v) == 0 {
		str := "failed to fetch aut coin"
		return nil, storeError(ErrDatabase, str, fmt.Errorf("non-exst aut coin"))
	}

	autCoin := new(AUTCoin)
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

func existsRawAUTCoin(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketAUTPoint).Get(k)
}

func deleteRawAUTCoin(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketAUTPoint).Delete(k)
	if err != nil {
		str := "failed to delete aut coin"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func valueBlockDisabledAUTRootCoins(outpoints []*wire.OutPointAbe) []byte {
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
func putBlockDisabledAUTRootCoins(ns walletdb.ReadWriteBucket, blockHeight int32, blockHash chainhash.Hash, outpoints []*wire.OutPointAbe) error {
	k := canonicalBlock(blockHeight, blockHash)
	v := valueBlockDisabledAUTRootCoins(outpoints)

	err := ns.NestedReadWriteBucket(bucketBlockDisabledAUTPoint).Put(k, v)
	if err != nil {
		str := "failed to put disable aut points"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchBlockDisabledAUTRootCoins(ns walletdb.ReadWriteBucket, k []byte) ([]*wire.OutPointAbe, error) {
	v := ns.NestedReadBucket(bucketBlockDisabledAUTPoint).Get(k)
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
func deleteBlockDisabledAUTRootCoins(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockDisabledAUTPoint).Delete(k)
	if err != nil {
		str := "failed to delete block input"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// bucketAUTEntry:[autName -> [outpoint->aut coins]
func spendAUTCoin(ns walletdb.ReadWriteBucket, txHash chainhash.Hash, index uint8) (*AUTCoin, bool, error) {
	autCoin, err := fetchRawAUTCoin(ns, txHash, index)
	if err != nil {
		return nil, false, err
	}

	// record the status of aut coin to distinguish that is consumed or just disabled
	spent := autCoin.Spent
	autCoin.Spent = true

	err = putRawAUTCoin(ns, txHash, index, autCoin)
	if err != nil {
		str := "failed to spent aut coin"
		return nil, false, storeError(ErrDatabase, str, err)
	}

	return autCoin, spent, nil
}

func restoreAUTCoin(ns walletdb.ReadWriteBucket, txHash chainhash.Hash, index uint8) (*AUTCoin, error) {
	autCoin, err := fetchRawAUTCoin(ns, txHash, index)
	if err != nil {
		return nil, err
	}

	autCoin.Spent = false

	err = putRawAUTCoin(ns, txHash, index, autCoin)
	if err != nil {
		str := "failed to spent aut coin"
		return nil, storeError(ErrDatabase, str, err)
	}

	return autCoin, nil
}
