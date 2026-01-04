package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/abeutil"
	ctautapi "github.com/abesuite/abec/ctaut/api"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewalletmlp/waddrmgr"
	"github.com/abesuite/abewalletmlp/wallet/txauthor"
	"github.com/abesuite/abewalletmlp/walletdb"
	"github.com/abesuite/abewalletmlp/wtxmgr"
)

func sortAndFindOutStart(abelOutDescs []*abecryptox.AbeTxOutputDesc) int {
	// sort abel output desc
	sort.SliceStable(abelOutDescs, func(i, j int) bool {
		outputIAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abelOutDescs[i].CryptoAddress())
		outputJAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abelOutDescs[j].CryptoAddress())

		// Part I  [crypto.PrivacyLevelFullPrivacyPre, crypto.PrivacyLevelFullPrivacyRand]
		// Part II [abecryptoxkey.PrivacyLevelPSEUDONYM, abecryptoxkey.PrivacyLevelPSEUDONYMCT]
		if outputIAddressPrivacyLevel < abecryptoxkey.PrivacyLevelPSEUDONYM &&
			outputJAddressPrivacyLevel >= abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}

		// Part I keep the origin order

		// Part II-I [ (abecryptoxkey.PrivacyLevelPSEUDONYMCT,1) (abecryptoxkey.PrivacyLevelPSEUDONYMCT,1) ... ]
		if outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			if abelOutDescs[i].Value() == 1 && abelOutDescs[j].Value() != 1 {
				return true
			}
			return false
		}

		// Part II-II [ (abecryptoxkey.PrivacyLevelPSEUDONYMCT,*) (abecryptoxkey.PrivacyLevelPSEUDONYM,*) ]
		if outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}
		if outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return false
		}

		return false
	})

	// find outStartIndex
	outStartIndex := -1
	for i := 0; i < len(abelOutDescs); i++ {
		outputIAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abelOutDescs[i].CryptoAddress())
		if outputIAddressPrivacyLevel != abecryptoxkey.PrivacyLevelRINGCTPre &&
			outputIAddressPrivacyLevel != abecryptoxkey.PrivacyLevelRINGCT {
			outStartIndex = i
			break
		}
	}
	if outStartIndex == -1 {
		outStartIndex = len(abelOutDescs)
	}

	return outStartIndex
}

func sortAndFindInStart(selectedTxos []*wtxmgr.SpendableTXO) int {
	sort.SliceStable(selectedTxos, func(i, j int) bool {
		coinAddressIPseudonymous := selectedTxos[i].IsPseudonymous() || selectedTxos[i].IsPseudonymousCT()
		coinAddressJPseudonymous := selectedTxos[j].IsPseudonymous() || selectedTxos[j].IsPseudonymousCT()
		// Part I  [crypto.PrivacyLevelFullPrivacyPre, crypto.PrivacyLevelFullPrivacyRand]
		// Part II [crypto.PrivacyLevelPseudonym, crypto.PrivacyLevelPseudonymCT]
		if !coinAddressIPseudonymous && coinAddressJPseudonymous {
			return true
		}

		// Part I keep the origin order

		// Part II-I [ (crypto.PrivacyLevelPseudonymCT,1) (crypto.PrivacyLevelPseudonymCT,1) ... ]
		if selectedTxos[i].IsPseudonymousCT() && selectedTxos[j].IsPseudonymousCT() {
			return false
		}

		// Part II-II [ (crypto.PrivacyLevelPseudonymCT,*) (crypto.PrivacyLevelPseudonym,*) ]
		if selectedTxos[i].IsPseudonymousCT() && selectedTxos[j].IsPseudonymous() {
			return true
		}
		if selectedTxos[j].IsPseudonymousCT() && selectedTxos[i].IsPseudonymous() {
			return false
		}

		return false
	})

	//  found inStartIndex
	inStartIndex := -1
	for i := 0; i < len(selectedTxos); i++ {
		if selectedTxos[i].IsPseudonymous() || selectedTxos[i].IsPseudonymousCT() {
			inStartIndex = i
			break
		}
	}
	if inStartIndex == -1 {
		inStartIndex = len(selectedTxos)
	}

	return inStartIndex
}

func (w *Wallet) txPqringCTToOutputsCTAUTRegister(txr *createTxCTAUTRegisterRequest) (unsignedTx *txauthor.AuthoredTxAbe, err error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return nil, err
		}
		log.Debug("Chain backend synced to tip!")
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	txVersion := wire.TxVersion
	targetValue := abeutil.Amount(0)
	outputPublic := int64(0)
	outForRing := 0

	outputCoinAddresses := make([][]byte, len(txr.autTxOutDescs))
	for i := 0; i < len(txr.autTxOutDescs); i++ {
		privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(txr.autTxOutDescs[i].CryptoAddress())
		if err != nil {
			return nil, err
		}
		outputCoinAddresses[i] = coinAddress
		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return nil, errors.New("unsupported address type for aut")
		}
		value := txr.autTxOutDescs[i].Value()
		outputPublic += int64(value)
		targetValue += abeutil.Amount(value)
	}

	if targetValue < 0 || targetValue > abeutil.Amount(abeutil.MaxNeutrino) {
		return nil, fmt.Errorf("target output value %v exceeds the maximum allowd value %v", targetValue, abeutil.MaxNeutrino)
	}

	maxOutputNum, err := abecryptoxparam.GetTxOutputMaxNum(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}

	maxNumOutputForRing, err := abecryptoxparam.GetTxOutputMaxNumForRing(txVersion)
	if err != nil {
		return nil, err
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}

	maxNumOutputForSingle, err := abecryptoxparam.GetTxOutputMaxNumForSingle(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	var eligible []wtxmgr.SpendableTXO
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		//eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		eligible, err = w.findEligibleTxosAbe(txmgrNs, txr.minconf, bs)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	autpointStr := make(map[string]struct{}, len(txr.outpoints))
	// outpoints would be selected
	for i := 0; i < len(txr.outpoints); i++ {
		autpointStr[txr.outpoints[i].String()] = struct{}{}
	}

	selectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(eligible))

	remainUTXOs := make([]*wtxmgr.SpendableTXO, 0)
	utxosforAUT := make(map[string]*wtxmgr.SpendableTXO, len(txr.outpoints))
	for i := 0; i < len(eligible); i++ {
		if !eligible[i].IsCTAUTCoin() {
			remainUTXOs = append(remainUTXOs, &eligible[i])
			continue
		}
		_, isSpecifiedAUTPoint := autpointStr[eligible[i].TxOutput.String()]
		if !isSpecifiedAUTPoint {
			continue
		}
		utxosforAUT[eligible[i].TxOutput.String()] = &eligible[i]
	}
	if len(utxosforAUT) != len(txr.outpoints) {
		return nil, errors.New("not all specified AUT coins can be selected for generate transaction")
	}
	for i := 0; i < len(txr.outpoints); i++ {
		selectedTxos = append(selectedTxos, utxosforAUT[txr.outpoints[i].String()])
	}

	if len(txr.utxoSpecified) != 0 {
		utxoSpecifiedMapping := map[string]struct{}{}
		for i := 0; i < len(txr.utxoSpecified); i++ {
			utxoSpecifiedMapping[txr.utxoSpecified[i]] = struct{}{}
		}

		specifiedTxo := make([]*wtxmgr.SpendableTXO, 0, len(txr.utxoSpecified))
		for i := 0; i < len(remainUTXOs); i++ {
			if _, exist := utxoSpecifiedMapping[remainUTXOs[i].Hash().String()]; !exist {
				continue
			}
			specifiedTxo = append(specifiedTxo, remainUTXOs[i])
		}
		if len(specifiedTxo) != len(txr.utxoSpecified) {
			return nil, errors.New("not all specified utxo can be selected for generate transaction")
		}

		selectedTxos = append(selectedTxos, specifiedTxo...)
	} else {
		inputRingVersionsForAll := make([]uint32, 0, len(selectedTxos)+len(remainUTXOs))
		inRingSizesForAll := make([]uint8, 0, len(selectedTxos)+len(remainUTXOs))
		inputPublic := uint64(0)
		inForSingleDistinct := uint8(0)

		var currentTotal abeutil.Amount
		tmpSelectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(selectedTxos))
		publicRandMapping := make(map[string]struct{}, len(selectedTxos)+len(remainUTXOs))
		for _, txo := range selectedTxos {
			inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
			inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
			inputPublic += txo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
			}
			currentTotal += abeutil.Amount(txo.Amount)
			tmpSelectedTxos = append(tmpSelectedTxos, txo)
		}

		var tmpFee abeutil.Amount

		nextUTXOIdx := 0
		for nextUTXOIdx < len(remainUTXOs) {
			currentUtxo := remainUTXOs[nextUTXOIdx]
			nextUTXOIdx++

			// avoid unconscious burn
			if currentUtxo.IsCTAUTCoin() {
				continue
			}

			inputRingVersionsForAll = append(inputRingVersionsForAll, currentUtxo.Version)
			inRingSizesForAll = append(inRingSizesForAll, currentUtxo.RingSize)
			currentTotal += abeutil.Amount(currentUtxo.Amount)

			inputPublic += currentUtxo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)] = struct{}{}
			}

			tmpSelectedTxos = append(tmpSelectedTxos, currentUtxo)
			if currentTotal < targetValue {
				continue
			}

			txConSize, err := wire.PrecomputeTrTxConSizeMLP(txVersion, inputRingVersionsForAll, inRingSizesForAll, outputCoinAddresses, abecryptoxparam.MaxAllowedTxMemoSize)
			if err != nil {
				return nil, err
			}
			witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(txVersion, 0, inForSingleDistinct, nil, 0 /*outputPublic-int64(inputPublic)*/, 0)
			if err != nil {
				return nil, err
			}
			tmpFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
			if err != nil {
				return nil, err
			}
			if currentTotal >= targetValue+tmpFee {
				selectedTxos = tmpSelectedTxos
				break
			}
		}
		if currentTotal < targetValue+tmpFee {
			return nil, errors.New("not enough ABEL to provide fee")
		}
	}

	// estimate transaction fee
	var txFee abeutil.Amount

	publicRandMapping := make(map[string]struct{}, len(selectedTxos)+len(remainUTXOs))
	inputRingVersionsForAll := make([]uint32, 0, len(selectedTxos)+len(remainUTXOs))
	inRingSizesForAll := make([]uint8, 0, len(selectedTxos)+len(remainUTXOs))
	inputPublic := uint64(0)
	inForSingleDistinct := uint8(0)

	var currentTotal abeutil.Amount
	for i := 0; i < len(selectedTxos); i++ {
		txo := selectedTxos[i]

		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}
	txConSize, err := wire.PrecomputeTrTxConSizeMLP(txVersion, inputRingVersionsForAll, inRingSizesForAll, outputCoinAddresses, abecryptoxparam.MaxAllowedTxMemoSize)
	if err != nil {
		return nil, err
	}
	witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(txVersion, 0, inForSingleDistinct, nil, 0 /*outputPublic-int64(inputPublic)*/, 0)
	if err != nil {
		return nil, err
	}
	txFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
	if err != nil {
		return nil, err
	}
	if currentTotal < targetValue+txFee {
		return nil, errors.New("the total amount of selected inputs is not enough to pay fee")
	}

	abelOutDescs := make([]*abecryptox.AbeTxOutputDesc, 0)

	if change := currentTotal - txFee - targetValue; change > 0 {
		// compute ABEL change
		var addrBytes []byte
		// fetch a free address if possible
		_, addrBytes, err = w.NewAddressKey(txr.changePrivacyLevel)
		if err != nil {
			return nil, err
		}

		if txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre || txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			outForRing += 1
		}

		abelOutDescs = append(abelOutDescs, abecryptox.NewAbeTxOutDesc(addrBytes, uint64(change)))
	}

	// sort abel output desc
	outStartIndex := sortAndFindOutStart(abelOutDescs)
	abelOutDescs = slices.Insert(abelOutDescs, outStartIndex, txr.autTxOutDescs...)

	if len(abelOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	autScript := ctautapi.NewRegistrationScript(txr.scriptVersion,
		[]byte(txr.name), []byte(txr.symbol),
		[]byte(txr.baseUnitName), []byte(txr.subUnitName), txr.unitScale,
		[]byte(txr.autMemo), txr.plannedTotalSupply,
		txr.issuers, txr.reregistrationExpireHeight,
		txr.reregisterThreshold, txr.mintThreshold,
		txr.privacyType,
		uint8(outStartIndex), uint8(len(txr.autTxOutDescs)),
		txr.scriptMemo)

	packagedAutScript, err := ctautapi.PackageAutScript(autScript)
	if err != nil {
		return nil, fmt.Errorf("fail to package aut script: %v", err)
	}

	tx, err := w.createTransactionMLPByRootSeeds(selectedTxos, abelOutDescs, packagedAutScript, txFee,
		false, abecryptoxkey.PrivacyLevelPSEUDONYMCT, false)
	if err != nil {
		return nil, err
	}
	tx.Tx.AutWitness = nil
	return tx, nil
}

func (w *Wallet) txPqringCTToOutputsCTAUTReRegister(txr *createTxCTAUTReRegisterRequest) (unsignedTx *txauthor.AuthoredTxAbe, err error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return nil, err
		}
		log.Debug("Chain backend synced to tip!")
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	txVersion := wire.TxVersion
	targetValue := abeutil.Amount(0)
	outputPublic := int64(0)
	outForRing := 0

	outputCoinAddresses := make([][]byte, len(txr.autTxOutDescs))
	for i := 0; i < len(txr.autTxOutDescs); i++ {
		privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(txr.autTxOutDescs[i].CryptoAddress())
		if err != nil {
			return nil, err
		}
		outputCoinAddresses[i] = coinAddress
		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return nil, errors.New("unsupported address type for aut")
		}
		value := txr.autTxOutDescs[i].Value()
		outputPublic += int64(value)
		targetValue += abeutil.Amount(value)
	}

	if targetValue < 0 || targetValue > abeutil.Amount(abeutil.MaxNeutrino) {
		return nil, fmt.Errorf("target output value %v exceeds the maximum allowd value %v", targetValue, abeutil.MaxNeutrino)
	}

	maxOutputNum, err := abecryptoxparam.GetTxOutputMaxNum(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}

	maxNumOutputForRing, err := abecryptoxparam.GetTxOutputMaxNumForRing(txVersion)
	if err != nil {
		return nil, err
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}

	maxNumOutputForSingle, err := abecryptoxparam.GetTxOutputMaxNumForSingle(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	var eligible []wtxmgr.SpendableTXO
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		//eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		eligible, err = w.findEligibleTxosAbe(txmgrNs, txr.minconf, bs)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	autpointStr := make(map[string]struct{}, len(txr.hostedOutpoints))
	// outpoints would be selected
	for i := 0; i < len(txr.hostedOutpoints); i++ {
		autpointStr[txr.hostedOutpoints[i].String()] = struct{}{}
	}

	selectedAUTTxos := make([]*wtxmgr.SpendableTXO, 0, len(eligible))

	remainUTXOs := make([]*wtxmgr.SpendableTXO, 0)
	utxosforAUT := make(map[string]*wtxmgr.SpendableTXO, len(txr.hostedOutpoints))
	for i := 0; i < len(eligible); i++ {
		if !eligible[i].IsCTAUTCoin() {
			remainUTXOs = append(remainUTXOs, &eligible[i])
			continue
		}
		_, isSpecifiedAUTPoint := autpointStr[eligible[i].TxOutput.String()]
		if !isSpecifiedAUTPoint {
			continue
		}
		utxosforAUT[eligible[i].TxOutput.String()] = &eligible[i]
	}
	if len(utxosforAUT) != len(txr.hostedOutpoints) {
		return nil, errors.New("not all specified AUT coins can be selected for generate transaction")
	}
	for i := 0; i < len(txr.hostedOutpoints); i++ {
		selectedAUTTxos = append(selectedAUTTxos, utxosforAUT[txr.hostedOutpoints[i].String()])
	}

	selectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(remainUTXOs))
	if len(txr.utxoSpecified) != 0 {
		utxoSpecifiedMapping := map[string]struct{}{}
		for i := 0; i < len(txr.utxoSpecified); i++ {
			utxoSpecifiedMapping[txr.utxoSpecified[i]] = struct{}{}
		}

		specifiedTxo := make([]*wtxmgr.SpendableTXO, 0, len(txr.utxoSpecified))
		for i := 0; i < len(remainUTXOs); i++ {
			if _, exist := utxoSpecifiedMapping[remainUTXOs[i].Hash().String()]; !exist {
				continue
			}
			specifiedTxo = append(specifiedTxo, remainUTXOs[i])
		}
		if len(specifiedTxo) != len(txr.utxoSpecified) {
			return nil, errors.New("not all specified utxo can be selected for generate transaction")
		}

		selectedTxos = append(selectedTxos, specifiedTxo...)
	} else {
		inputRingVersionsForAll := make([]uint32, 0, len(selectedTxos)+len(remainUTXOs))
		inRingSizesForAll := make([]uint8, 0, len(selectedTxos)+len(remainUTXOs))
		inputPublic := uint64(0)
		inForSingleDistinct := uint8(0)

		var currentTotal abeutil.Amount
		tmpSelectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(selectedTxos))
		publicRandMapping := make(map[string]struct{}, len(selectedTxos)+len(remainUTXOs))
		for _, txo := range selectedTxos {
			inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
			inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
			inputPublic += txo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
			}
			currentTotal += abeutil.Amount(txo.Amount)
			tmpSelectedTxos = append(tmpSelectedTxos, txo)
		}

		var tmpFee abeutil.Amount

		nextUTXOIdx := 0
		for nextUTXOIdx < len(remainUTXOs) {
			currentUtxo := remainUTXOs[nextUTXOIdx]
			nextUTXOIdx++

			// avoid unconscious burn
			if currentUtxo.IsCTAUTCoin() {
				continue
			}

			inputRingVersionsForAll = append(inputRingVersionsForAll, currentUtxo.Version)
			inRingSizesForAll = append(inRingSizesForAll, currentUtxo.RingSize)
			currentTotal += abeutil.Amount(currentUtxo.Amount)

			inputPublic += currentUtxo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)] = struct{}{}
			}

			tmpSelectedTxos = append(tmpSelectedTxos, currentUtxo)
			if currentTotal < targetValue {
				continue
			}

			txConSize, err := wire.PrecomputeTrTxConSizeMLP(txVersion, inputRingVersionsForAll, inRingSizesForAll, outputCoinAddresses, abecryptoxparam.MaxAllowedTxMemoSize)
			if err != nil {
				return nil, err
			}
			witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(txVersion, 0, inForSingleDistinct, nil, 0 /*outputPublic-int64(inputPublic)*/, 0)
			if err != nil {
				return nil, err
			}
			tmpFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
			if err != nil {
				return nil, err
			}
			if currentTotal >= targetValue+tmpFee {
				selectedTxos = tmpSelectedTxos
				break
			}
		}
		if currentTotal < targetValue+tmpFee {
			return nil, errors.New("not enough ABEL to provide fee")
		}
	}

	// estimate transaction fee
	var txFee abeutil.Amount

	publicRandMapping := make(map[string]struct{}, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inputRingVersionsForAll := make([]uint32, 0, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inRingSizesForAll := make([]uint8, 0, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inputPublic := uint64(0)
	inForSingleDistinct := uint8(0)

	var currentTotal abeutil.Amount
	for i := 0; i < len(selectedTxos); i++ {
		txo := selectedTxos[i]

		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}
	for i := 0; i < len(selectedAUTTxos); i++ {
		txo := selectedAUTTxos[i]
		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}

	txConSize, err := wire.PrecomputeTrTxConSizeMLP(
		txVersion,
		inputRingVersionsForAll, inRingSizesForAll,
		outputCoinAddresses,
		abecryptoxparam.MaxAllowedTxMemoSize,
	)
	if err != nil {
		return nil, err
	}
	witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(
		txVersion,
		0,
		inForSingleDistinct,
		nil,
		0, /*outputPublic-int64(inputPublic)*/
		0)
	if err != nil {
		return nil, err
	}
	txFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
	if err != nil {
		return nil, err
	}
	if currentTotal < targetValue+txFee {
		return nil, errors.New("the total amount of selected inputs is not enough to pay fee")
	}

	abelOutDescs := make([]*abecryptox.AbeTxOutputDesc, 0)

	if change := currentTotal - txFee - targetValue; change > 0 {
		// compute ABEL change
		var addrBytes []byte
		// fetch a free address if possible
		_, addrBytes, err = w.NewAddressKey(txr.changePrivacyLevel)
		if err != nil {
			return nil, err
		}

		if txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre || txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			outForRing += 1
		}

		abelOutDescs = append(abelOutDescs, abecryptox.NewAbeTxOutDesc(addrBytes, uint64(change)))
	}

	// sort abel output desc and insert
	outStartIndex := sortAndFindOutStart(abelOutDescs)
	abelOutDescs = slices.Insert(abelOutDescs, outStartIndex, txr.autTxOutDescs...)

	if len(abelOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	// sort
	inStartIndex := sortAndFindInStart(selectedTxos)
	selectedTxos = slices.Insert(selectedTxos, inStartIndex, selectedAUTTxos...)
	// TODO check the input

	autScript := ctautapi.NewReRegistrationScript(
		txr.scriptVersion,
		txr.identifier,
		txr.autMemo, txr.plannedTotalSupply,
		txr.issuers, txr.reregistrationExpireHeight,
		txr.reregisterThreshold, txr.mintThreshold,
		txr.privacyType,
		uint8(inStartIndex), uint8(len(txr.hostedOutpoints)),
		uint8(outStartIndex), uint8(len(txr.autTxOutDescs)),
		txr.scriptMemo,
	)

	packagedAutScript, err := ctautapi.PackageAutScript(autScript)
	if err != nil {
		return nil, fmt.Errorf("fail to package aut script: %v", err)
	}

	tx, err := w.createTransactionMLPByRootSeeds(selectedTxos, abelOutDescs, packagedAutScript, txFee,
		false, abecryptoxkey.PrivacyLevelPSEUDONYMCT, false)
	if err != nil {
		return nil, err
	}
	tx.Tx.AutWitness = nil
	return tx, nil
}
func (w *Wallet) txPqringCTToOutputsCTAUTMint(txr *createTxCTAUTMintRequest) (unsignedTx *txauthor.AuthoredTxAbe, err error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return nil, err
		}
		log.Debug("Chain backend synced to tip!")
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	txVersion := wire.TxVersion
	targetValue := abeutil.Amount(0)
	outputPublic := int64(0)
	outForRing := 0

	outputCoinAddresses := make([][]byte, len(txr.autTxOutDescs))
	for i := 0; i < len(txr.autTxOutDescs); i++ {
		privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(txr.autTxOutDescs[i].CryptoAddress())
		if err != nil {
			return nil, err
		}
		outputCoinAddresses[i] = coinAddress
		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return nil, errors.New("unsupported address type for aut")
		}
		value := txr.autTxOutDescs[i].Value()
		outputPublic += int64(value)
		targetValue += abeutil.Amount(value)
	}

	if targetValue < 0 || targetValue > abeutil.Amount(abeutil.MaxNeutrino) {
		return nil, fmt.Errorf("target output value %v exceeds the maximum allowd value %v", targetValue, abeutil.MaxNeutrino)
	}

	maxOutputNum, err := abecryptoxparam.GetTxOutputMaxNum(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}

	maxNumOutputForRing, err := abecryptoxparam.GetTxOutputMaxNumForRing(txVersion)
	if err != nil {
		return nil, err
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}

	maxNumOutputForSingle, err := abecryptoxparam.GetTxOutputMaxNumForSingle(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	var eligible []wtxmgr.SpendableTXO
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		//eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		eligible, err = w.findEligibleTxosAbe(txmgrNs, txr.minconf, bs)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	autpointStr := make(map[string]struct{}, len(txr.hostedOutpoints))
	// outpoints would be selected
	for i := 0; i < len(txr.hostedOutpoints); i++ {
		autpointStr[txr.hostedOutpoints[i].String()] = struct{}{}
	}

	selectedAUTTxos := make([]*wtxmgr.SpendableTXO, 0, len(eligible))

	remainUTXOs := make([]*wtxmgr.SpendableTXO, 0)
	utxosforAUT := make(map[string]*wtxmgr.SpendableTXO, len(txr.hostedOutpoints))
	for i := 0; i < len(eligible); i++ {
		if !eligible[i].IsCTAUTCoin() {
			remainUTXOs = append(remainUTXOs, &eligible[i])
			continue
		}
		_, isSpecifiedAUTPoint := autpointStr[eligible[i].TxOutput.String()]
		if !isSpecifiedAUTPoint {
			continue
		}
		utxosforAUT[eligible[i].TxOutput.String()] = &eligible[i]
	}
	if len(utxosforAUT) != len(txr.hostedOutpoints) {
		return nil, errors.New("not all specified AUT coins can be selected for generate transaction")
	}
	for i := 0; i < len(txr.hostedOutpoints); i++ {
		selectedAUTTxos = append(selectedAUTTxos, utxosforAUT[txr.hostedOutpoints[i].String()])
	}

	selectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(remainUTXOs))
	if len(txr.utxoSpecified) != 0 {
		utxoSpecifiedMapping := map[string]struct{}{}
		for i := 0; i < len(txr.utxoSpecified); i++ {
			utxoSpecifiedMapping[txr.utxoSpecified[i]] = struct{}{}
		}

		specifiedTxo := make([]*wtxmgr.SpendableTXO, 0, len(txr.utxoSpecified))
		for i := 0; i < len(remainUTXOs); i++ {
			if _, exist := utxoSpecifiedMapping[remainUTXOs[i].Hash().String()]; !exist {
				continue
			}
			specifiedTxo = append(specifiedTxo, remainUTXOs[i])
		}
		if len(specifiedTxo) != len(txr.utxoSpecified) {
			return nil, errors.New("not all specified utxo can be selected for generate transaction")
		}

		selectedTxos = append(selectedTxos, specifiedTxo...)
	} else {
		inputRingVersionsForAll := make([]uint32, 0, len(selectedTxos)+len(remainUTXOs))
		inRingSizesForAll := make([]uint8, 0, len(selectedTxos)+len(remainUTXOs))
		inputPublic := uint64(0)
		inForSingleDistinct := uint8(0)

		var currentTotal abeutil.Amount
		tmpSelectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(selectedTxos))
		publicRandMapping := make(map[string]struct{}, len(selectedTxos)+len(remainUTXOs))
		for _, txo := range selectedTxos {
			inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
			inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
			inputPublic += txo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
			}
			currentTotal += abeutil.Amount(txo.Amount)
			tmpSelectedTxos = append(tmpSelectedTxos, txo)
		}

		var tmpFee abeutil.Amount

		nextUTXOIdx := 0
		for nextUTXOIdx < len(remainUTXOs) {
			currentUtxo := remainUTXOs[nextUTXOIdx]
			nextUTXOIdx++

			// avoid unconscious burn
			if currentUtxo.IsCTAUTCoin() {
				continue
			}

			inputRingVersionsForAll = append(inputRingVersionsForAll, currentUtxo.Version)
			inRingSizesForAll = append(inRingSizesForAll, currentUtxo.RingSize)
			currentTotal += abeutil.Amount(currentUtxo.Amount)

			inputPublic += currentUtxo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)] = struct{}{}
			}

			tmpSelectedTxos = append(tmpSelectedTxos, currentUtxo)
			if currentTotal < targetValue {
				continue
			}

			txConSize, err := wire.PrecomputeTrTxConSizeMLP(txVersion, inputRingVersionsForAll, inRingSizesForAll, outputCoinAddresses, abecryptoxparam.MaxAllowedTxMemoSize)
			if err != nil {
				return nil, err
			}
			witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(txVersion, 0, inForSingleDistinct, nil, 0 /*outputPublic-int64(inputPublic)*/, 0)
			if err != nil {
				return nil, err
			}
			tmpFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
			if err != nil {
				return nil, err
			}
			if currentTotal >= targetValue+tmpFee {
				selectedTxos = tmpSelectedTxos
				break
			}
		}
		if currentTotal < targetValue+tmpFee {
			return nil, errors.New("not enough ABEL to provide fee")
		}
	}

	// estimate transaction fee
	var txFee abeutil.Amount

	publicRandMapping := make(map[string]struct{}, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inputRingVersionsForAll := make([]uint32, 0, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inRingSizesForAll := make([]uint8, 0, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inputPublic := uint64(0)
	inForSingleDistinct := uint8(0)

	var currentTotal abeutil.Amount
	for i := 0; i < len(selectedTxos); i++ {
		txo := selectedTxos[i]

		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}
	for i := 0; i < len(selectedAUTTxos); i++ {
		txo := selectedAUTTxos[i]
		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}

	txConSize, err := wire.PrecomputeTrTxConSizeMLP(
		txVersion,
		inputRingVersionsForAll, inRingSizesForAll,
		outputCoinAddresses,
		abecryptoxparam.MaxAllowedTxMemoSize,
	)
	if err != nil {
		return nil, err
	}
	witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(
		txVersion,
		0,
		inForSingleDistinct,
		nil,
		0, /*outputPublic-int64(inputPublic)*/
		0)
	if err != nil {
		return nil, err
	}
	txFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
	if err != nil {
		return nil, err
	}
	if currentTotal < targetValue+txFee {
		return nil, errors.New("the total amount of selected inputs is not enough to pay fee")
	}

	abelOutDescs := make([]*abecryptox.AbeTxOutputDesc, 0)

	if change := currentTotal - txFee - targetValue; change > 0 {
		// compute ABEL change
		var addrBytes []byte
		// fetch a free address if possible
		_, addrBytes, err = w.NewAddressKey(txr.changePrivacyLevel)
		if err != nil {
			return nil, err
		}

		if txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre || txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			outForRing += 1
		}

		abelOutDescs = append(abelOutDescs, abecryptox.NewAbeTxOutDesc(addrBytes, uint64(change)))
	}

	// sort abel output desc
	outStartIndex := sortAndFindOutStart(abelOutDescs)
	abelOutDescs = slices.Insert(abelOutDescs, outStartIndex, txr.autTxOutDescs...)

	if len(abelOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	// sort
	inStartIndex := sortAndFindInStart(selectedTxos)
	selectedTxos = slices.Insert(selectedTxos, inStartIndex, selectedAUTTxos...)

	autCoinbaseTx, err := abecryptox.AutCoinbaseTxGen(txr.scriptVersion, txr.vin, txr.autCoinbaseTxOutputDescs)
	if err != nil {
		return nil, err
	}
	if len(autCoinbaseTx.TxOuts) != len(txr.autCoinbaseTxOutputDescs) {
		return nil, fmt.Errorf("the number of outputs is not equal to the number of output descriptions")
	}
	valueScripts := make([][]byte, len(autCoinbaseTx.TxOuts))
	for i := 0; i < len(autCoinbaseTx.TxOuts); i++ {
		valueScripts[i], err = autCoinbaseTx.TxOuts[i].Serialize()
		if err != nil {
			return nil, err
		}
	}
	witnessHash := ctautwire.AutWitnessHash(autCoinbaseTx.TxWitness)

	autScript := ctautapi.NewMintScript(
		txr.scriptVersion,
		txr.identifier,
		txr.vin,
		uint8(inStartIndex), uint8(len(txr.hostedOutpoints)),
		uint8(outStartIndex), txr.outCTAutTokenNum, txr.outPlainAutTokenNum,
		valueScripts,
		txr.scriptMemo,
		witnessHash,
	)

	packagedAutScript, err := ctautapi.PackageAutScript(autScript)
	if err != nil {
		return nil, fmt.Errorf("fail to package aut script: %v", err)
	}

	tx, err := w.createTransactionMLPByRootSeeds(selectedTxos, abelOutDescs, packagedAutScript, txFee,
		false, abecryptoxkey.PrivacyLevelPSEUDONYMCT, false)
	if err != nil {
		return nil, err
	}
	tx.Tx.AutWitness = autCoinbaseTx.TxWitness
	return tx, nil
}

func (w *Wallet) txPqringCTToOutputsCTAUTTransfer(txr *createTxCTAUTTransferRequest) (unsignedTx *txauthor.AuthoredTxAbe, err error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return nil, err
		}
		log.Debug("Chain backend synced to tip!")
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	txVersion := wire.TxVersion
	targetValue := abeutil.Amount(0)
	outputPublic := int64(0)
	outForRing := 0

	outputCoinAddresses := make([][]byte, len(txr.autTxOutDescs))
	for i := 0; i < len(txr.autTxOutDescs); i++ {
		privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(txr.autTxOutDescs[i].CryptoAddress())
		if err != nil {
			return nil, err
		}
		outputCoinAddresses[i] = coinAddress
		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return nil, errors.New("unsupported address type for aut")
		}
		value := txr.autTxOutDescs[i].Value()
		outputPublic += int64(value)
		targetValue += abeutil.Amount(value)
	}

	if targetValue < 0 || targetValue > abeutil.Amount(abeutil.MaxNeutrino) {
		return nil, fmt.Errorf("target output value %v exceeds the maximum allowd value %v", targetValue, abeutil.MaxNeutrino)
	}

	maxOutputNum, err := abecryptoxparam.GetTxOutputMaxNum(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}

	maxNumOutputForRing, err := abecryptoxparam.GetTxOutputMaxNumForRing(txVersion)
	if err != nil {
		return nil, err
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}

	maxNumOutputForSingle, err := abecryptoxparam.GetTxOutputMaxNumForSingle(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	var eligible []wtxmgr.SpendableTXO
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		//eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		eligible, err = w.findEligibleTxosAbe(txmgrNs, txr.minconf, bs)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	autpointStr := make(map[string]struct{}, len(txr.hostedOutpoints))
	// outpoints would be selected
	for i := 0; i < len(txr.hostedOutpoints); i++ {
		autpointStr[txr.hostedOutpoints[i].String()] = struct{}{}
	}

	selectedAUTTxos := make([]*wtxmgr.SpendableTXO, 0, len(eligible))

	remainUTXOs := make([]*wtxmgr.SpendableTXO, 0)
	utxosforAUT := make(map[string]*wtxmgr.SpendableTXO, len(txr.hostedOutpoints))
	for i := 0; i < len(eligible); i++ {
		if !eligible[i].IsCTAUTCoin() {
			remainUTXOs = append(remainUTXOs, &eligible[i])
			continue
		}
		_, isSpecifiedAUTPoint := autpointStr[eligible[i].TxOutput.String()]
		if !isSpecifiedAUTPoint {
			continue
		}
		utxosforAUT[eligible[i].TxOutput.String()] = &eligible[i]
	}
	if len(utxosforAUT) != len(txr.hostedOutpoints) {
		return nil, errors.New("not all specified AUT coins can be selected for generate transaction")
	}
	for i := 0; i < len(txr.hostedOutpoints); i++ {
		selectedAUTTxos = append(selectedAUTTxos, utxosforAUT[txr.hostedOutpoints[i].String()])
	}

	selectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(remainUTXOs))
	if len(txr.utxoSpecified) != 0 {
		utxoSpecifiedMapping := map[string]struct{}{}
		for i := 0; i < len(txr.utxoSpecified); i++ {
			utxoSpecifiedMapping[txr.utxoSpecified[i]] = struct{}{}
		}

		specifiedTxo := make([]*wtxmgr.SpendableTXO, 0, len(txr.utxoSpecified))
		for i := 0; i < len(remainUTXOs); i++ {
			if _, exist := utxoSpecifiedMapping[remainUTXOs[i].Hash().String()]; !exist {
				continue
			}
			specifiedTxo = append(specifiedTxo, remainUTXOs[i])
		}
		if len(specifiedTxo) != len(txr.utxoSpecified) {
			return nil, errors.New("not all specified utxo can be selected for generate transaction")
		}

		selectedTxos = append(selectedTxos, specifiedTxo...)
	} else {
		inputRingVersionsForAll := make([]uint32, 0, len(selectedTxos)+len(remainUTXOs))
		inRingSizesForAll := make([]uint8, 0, len(selectedTxos)+len(remainUTXOs))
		inputPublic := uint64(0)
		inForSingleDistinct := uint8(0)

		var currentTotal abeutil.Amount
		tmpSelectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(selectedTxos))
		publicRandMapping := make(map[string]struct{}, len(selectedTxos)+len(remainUTXOs))
		for _, txo := range selectedTxos {
			inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
			inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
			inputPublic += txo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
			}
			currentTotal += abeutil.Amount(txo.Amount)
			tmpSelectedTxos = append(tmpSelectedTxos, txo)
		}

		var tmpFee abeutil.Amount

		nextUTXOIdx := 0
		for nextUTXOIdx < len(remainUTXOs) {
			currentUtxo := remainUTXOs[nextUTXOIdx]
			nextUTXOIdx++

			// avoid unconscious burn
			if currentUtxo.IsCTAUTCoin() {
				continue
			}

			inputRingVersionsForAll = append(inputRingVersionsForAll, currentUtxo.Version)
			inRingSizesForAll = append(inRingSizesForAll, currentUtxo.RingSize)
			currentTotal += abeutil.Amount(currentUtxo.Amount)

			inputPublic += currentUtxo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)] = struct{}{}
			}

			tmpSelectedTxos = append(tmpSelectedTxos, currentUtxo)
			if currentTotal < targetValue {
				continue
			}

			txConSize, err := wire.PrecomputeTrTxConSizeMLP(txVersion, inputRingVersionsForAll, inRingSizesForAll, outputCoinAddresses, abecryptoxparam.MaxAllowedTxMemoSize)
			if err != nil {
				return nil, err
			}
			witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(txVersion, 0, inForSingleDistinct, nil, 0 /*outputPublic-int64(inputPublic)*/, 0)
			if err != nil {
				return nil, err
			}
			tmpFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
			if err != nil {
				return nil, err
			}
			if currentTotal >= targetValue+tmpFee {
				selectedTxos = tmpSelectedTxos
				break
			}
		}
		if currentTotal < targetValue+tmpFee {
			return nil, errors.New("not enough ABEL to provide fee")
		}
	}

	// estimate transaction fee
	var txFee abeutil.Amount

	publicRandMapping := make(map[string]struct{}, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inputRingVersionsForAll := make([]uint32, 0, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inRingSizesForAll := make([]uint8, 0, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inputPublic := uint64(0)
	inForSingleDistinct := uint8(0)

	var currentTotal abeutil.Amount
	for i := 0; i < len(selectedTxos); i++ {
		txo := selectedTxos[i]

		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}
	for i := 0; i < len(selectedAUTTxos); i++ {
		txo := selectedAUTTxos[i]
		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}

	txConSize, err := wire.PrecomputeTrTxConSizeMLP(
		txVersion,
		inputRingVersionsForAll, inRingSizesForAll,
		outputCoinAddresses,
		abecryptoxparam.MaxAllowedTxMemoSize,
	)
	if err != nil {
		return nil, err
	}
	witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(
		txVersion,
		0,
		inForSingleDistinct,
		nil,
		0, /*outputPublic-int64(inputPublic)*/
		0)
	if err != nil {
		return nil, err
	}
	txFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
	if err != nil {
		return nil, err
	}
	if currentTotal < targetValue+txFee {
		return nil, errors.New("the total amount of selected inputs is not enough to pay fee")
	}

	abelOutDescs := make([]*abecryptox.AbeTxOutputDesc, 0)

	if change := currentTotal - txFee - targetValue; change > 0 {
		// compute ABEL change
		var addrBytes []byte
		// fetch a free address if possible
		_, addrBytes, err = w.NewAddressKey(txr.changePrivacyLevel)
		if err != nil {
			return nil, err
		}

		if txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre || txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			outForRing += 1
		}

		abelOutDescs = append(abelOutDescs, abecryptox.NewAbeTxOutDesc(addrBytes, uint64(change)))
	}

	// sort abel output desc
	outStartIndex := sortAndFindOutStart(abelOutDescs)
	abelOutDescs = slices.Insert(abelOutDescs, outStartIndex, txr.autTxOutDescs...)

	if len(abelOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	// sort
	inStartIndex := sortAndFindInStart(selectedTxos)
	selectedTxos = slices.Insert(selectedTxos, inStartIndex, selectedAUTTxos...)
	// TODO check the input

	autTransferTx, err := abecryptox.AutTransferTxGen(txr.scriptVersion, txr.autTransferTxInputDescs, txr.autTransferTxOutputDescs)
	if err != nil {
		return nil, err
	}
	if len(autTransferTx.TxOuts) != len(txr.autTransferTxOutputDescs) {
		return nil, fmt.Errorf("the number of outputs is not equal to the number of output descriptions")
	}
	valueScripts := make([][]byte, len(autTransferTx.TxOuts))
	for i := 0; i < len(autTransferTx.TxOuts); i++ {
		valueScripts[i], err = autTransferTx.TxOuts[i].Serialize()
		if err != nil {
			return nil, err
		}
	}

	witnessHash := ctautwire.AutWitnessHash(autTransferTx.TxWitness)

	autScript := ctautapi.NewTransferScript(
		txr.scriptVersion,
		txr.identifier,
		uint8(inStartIndex), txr.inCTAUTTokenNum, txr.inPlainAUTTokenNum,
		uint8(outStartIndex), txr.outCTAutTokenNum, txr.outPlainAutTokenNum,
		valueScripts,
		txr.scriptMemo,
		witnessHash,
	)

	packagedAutScript, err := ctautapi.PackageAutScript(autScript)
	if err != nil {
		return nil, fmt.Errorf("fail to package aut script: %v", err)
	}

	tx, err := w.createTransactionMLPByRootSeeds(selectedTxos, abelOutDescs, packagedAutScript, txFee,
		false, abecryptoxkey.PrivacyLevelPSEUDONYMCT, false)
	if err != nil {
		return nil, err
	}
	tx.Tx.AutWitness = autTransferTx.TxWitness

	return tx, nil
}
func (w *Wallet) txPqringCTToOutputsCTAUTBurn(txr *createTxCTAUTBurnRequest) (unsignedTx *txauthor.AuthoredTxAbe, err error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return nil, err
		}
		log.Debug("Chain backend synced to tip!")
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	txVersion := wire.TxVersion
	targetValue := abeutil.Amount(0)
	outputPublic := int64(0)
	outForRing := 0

	outputCoinAddresses := make([][]byte, len(txr.autTxOutDescs))
	for i := 0; i < len(txr.autTxOutDescs); i++ {
		privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(txr.autTxOutDescs[i].CryptoAddress())
		if err != nil {
			return nil, err
		}
		outputCoinAddresses[i] = coinAddress
		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return nil, errors.New("unsupported address type for aut")
		}
		value := txr.autTxOutDescs[i].Value()
		outputPublic += int64(value)
		targetValue += abeutil.Amount(value)
	}

	if targetValue < 0 || targetValue > abeutil.Amount(abeutil.MaxNeutrino) {
		return nil, fmt.Errorf("target output value %v exceeds the maximum allowd value %v", targetValue, abeutil.MaxNeutrino)
	}

	maxOutputNum, err := abecryptoxparam.GetTxOutputMaxNum(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}

	maxNumOutputForRing, err := abecryptoxparam.GetTxOutputMaxNumForRing(txVersion)
	if err != nil {
		return nil, err
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}

	maxNumOutputForSingle, err := abecryptoxparam.GetTxOutputMaxNumForSingle(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	var eligible []wtxmgr.SpendableTXO
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		//eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		eligible, err = w.findEligibleTxosAbe(txmgrNs, txr.minconf, bs)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	autpointStr := make(map[string]struct{}, len(txr.hostedOutpoints))
	// outpoints would be selected
	for i := 0; i < len(txr.hostedOutpoints); i++ {
		autpointStr[txr.hostedOutpoints[i].String()] = struct{}{}
	}

	selectedAUTTxos := make([]*wtxmgr.SpendableTXO, 0, len(eligible))

	remainUTXOs := make([]*wtxmgr.SpendableTXO, 0)
	utxosforAUT := make(map[string]*wtxmgr.SpendableTXO, len(txr.hostedOutpoints))
	for i := 0; i < len(eligible); i++ {
		if !eligible[i].IsCTAUTCoin() {
			remainUTXOs = append(remainUTXOs, &eligible[i])
			continue
		}
		_, isSpecifiedAUTPoint := autpointStr[eligible[i].TxOutput.String()]
		if !isSpecifiedAUTPoint {
			continue
		}
		utxosforAUT[eligible[i].TxOutput.String()] = &eligible[i]
	}
	if len(utxosforAUT) != len(txr.hostedOutpoints) {
		return nil, errors.New("not all specified AUT coins can be selected for generate transaction")
	}
	for i := 0; i < len(txr.hostedOutpoints); i++ {
		selectedAUTTxos = append(selectedAUTTxos, utxosforAUT[txr.hostedOutpoints[i].String()])
	}

	selectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(remainUTXOs))
	if len(txr.utxoSpecified) != 0 {
		utxoSpecifiedMapping := map[string]struct{}{}
		for i := 0; i < len(txr.utxoSpecified); i++ {
			utxoSpecifiedMapping[txr.utxoSpecified[i]] = struct{}{}
		}

		specifiedTxo := make([]*wtxmgr.SpendableTXO, 0, len(txr.utxoSpecified))
		for i := 0; i < len(remainUTXOs); i++ {
			if _, exist := utxoSpecifiedMapping[remainUTXOs[i].Hash().String()]; !exist {
				continue
			}
			specifiedTxo = append(specifiedTxo, remainUTXOs[i])
		}
		if len(specifiedTxo) != len(txr.utxoSpecified) {
			return nil, errors.New("not all specified utxo can be selected for generate transaction")
		}

		selectedTxos = append(selectedTxos, specifiedTxo...)
	} else {
		inputRingVersionsForAll := make([]uint32, 0, len(selectedTxos)+len(remainUTXOs))
		inRingSizesForAll := make([]uint8, 0, len(selectedTxos)+len(remainUTXOs))
		inputPublic := uint64(0)
		inForSingleDistinct := uint8(0)

		var currentTotal abeutil.Amount
		tmpSelectedTxos := make([]*wtxmgr.SpendableTXO, 0, len(selectedTxos))
		publicRandMapping := make(map[string]struct{}, len(selectedTxos)+len(remainUTXOs))
		for _, txo := range selectedTxos {
			inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
			inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
			inputPublic += txo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
			}
			currentTotal += abeutil.Amount(txo.Amount)
			tmpSelectedTxos = append(tmpSelectedTxos, txo)
		}

		var tmpFee abeutil.Amount

		nextUTXOIdx := 0
		for nextUTXOIdx < len(remainUTXOs) {
			currentUtxo := remainUTXOs[nextUTXOIdx]
			nextUTXOIdx++

			// avoid unconscious burn
			if currentUtxo.IsCTAUTCoin() {
				continue
			}

			inputRingVersionsForAll = append(inputRingVersionsForAll, currentUtxo.Version)
			inRingSizesForAll = append(inRingSizesForAll, currentUtxo.RingSize)
			currentTotal += abeutil.Amount(currentUtxo.Amount)

			inputPublic += currentUtxo.Amount
			if _, ok := publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)]; !ok {
				inForSingleDistinct++
				publicRandMapping[hex.EncodeToString(currentUtxo.PublicRand)] = struct{}{}
			}

			tmpSelectedTxos = append(tmpSelectedTxos, currentUtxo)
			if currentTotal < targetValue {
				continue
			}

			txConSize, err := wire.PrecomputeTrTxConSizeMLP(txVersion, inputRingVersionsForAll, inRingSizesForAll, outputCoinAddresses, abecryptoxparam.MaxAllowedTxMemoSize)
			if err != nil {
				return nil, err
			}
			witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(txVersion, 0, inForSingleDistinct, nil, 0 /*outputPublic-int64(inputPublic)*/, 0)
			if err != nil {
				return nil, err
			}
			tmpFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
			if err != nil {
				return nil, err
			}
			if currentTotal >= targetValue+tmpFee {
				selectedTxos = tmpSelectedTxos
				break
			}
		}
		if currentTotal < targetValue+tmpFee {
			return nil, errors.New("not enough ABEL to provide fee")
		}
	}

	// estimate transaction fee
	var txFee abeutil.Amount

	publicRandMapping := make(map[string]struct{}, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inputRingVersionsForAll := make([]uint32, 0, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inRingSizesForAll := make([]uint8, 0, len(selectedAUTTxos)+len(selectedTxos)+len(remainUTXOs))
	inputPublic := uint64(0)
	inForSingleDistinct := uint8(0)

	var currentTotal abeutil.Amount
	for i := 0; i < len(selectedTxos); i++ {
		txo := selectedTxos[i]

		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}
	for i := 0; i < len(selectedAUTTxos); i++ {
		txo := selectedAUTTxos[i]
		inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
		inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
		currentTotal += abeutil.Amount(txo.Amount)

		inputPublic += txo.Amount
		if _, ok := publicRandMapping[hex.EncodeToString(txo.PublicRand)]; !ok {
			inForSingleDistinct++
			publicRandMapping[hex.EncodeToString(txo.PublicRand)] = struct{}{}
		}
	}

	txConSize, err := wire.PrecomputeTrTxConSizeMLP(
		txVersion,
		inputRingVersionsForAll, inRingSizesForAll,
		outputCoinAddresses,
		abecryptoxparam.MaxAllowedTxMemoSize,
	)
	if err != nil {
		return nil, err
	}
	witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(
		txVersion,
		0,
		inForSingleDistinct,
		nil,
		0, /*outputPublic-int64(inputPublic)*/
		0)
	if err != nil {
		return nil, err
	}
	txFee, err = CalculateFee(txConSize, uint32(witnessSize), txr.feePerKbSpecified)
	if err != nil {
		return nil, err
	}
	if currentTotal < targetValue+txFee {
		return nil, errors.New("the total amount of selected inputs is not enough to pay fee")
	}

	abelOutDescs := make([]*abecryptox.AbeTxOutputDesc, 0)

	if change := currentTotal - txFee - targetValue; change > 0 {
		// compute ABEL change
		var addrBytes []byte
		// fetch a free address if possible
		_, addrBytes, err = w.NewAddressKey(txr.changePrivacyLevel)
		if err != nil {
			return nil, err
		}

		if txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre || txr.changePrivacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			outForRing += 1
		}

		abelOutDescs = append(abelOutDescs, abecryptox.NewAbeTxOutDesc(addrBytes, uint64(change)))
	}

	// sort abel output desc
	outStartIndex := sortAndFindOutStart(abelOutDescs)
	abelOutDescs = slices.Insert(abelOutDescs, outStartIndex, txr.autTxOutDescs...)

	if len(abelOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}
	if len(txr.autTxOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txr.autTxOutDescs)-outForRing)
	}

	// sort
	inStartIndex := sortAndFindInStart(selectedTxos)
	selectedTxos = slices.Insert(selectedTxos, inStartIndex, selectedAUTTxos...)
	// TODO check the input

	autTransferTx, err := abecryptox.AutTransferTxGen(txr.scriptVersion, txr.autTransferTxInputDescs, txr.autTransferTxOutputDescs)
	if err != nil {
		return nil, err
	}
	if len(autTransferTx.TxOuts) != len(txr.autTransferTxOutputDescs) {
		return nil, fmt.Errorf("the number of outputs is not equal to the number of output descriptions")
	}
	valueScripts := make([][]byte, len(autTransferTx.TxOuts))
	for i := 0; i < len(autTransferTx.TxOuts); i++ {
		valueScripts[i], err = autTransferTx.TxOuts[i].Serialize()
		if err != nil {
			return nil, err
		}
	}

	witnessHash := ctautwire.AutWitnessHash(autTransferTx.TxWitness)

	autScript := ctautapi.NewBurnScript(
		txr.scriptVersion,
		txr.identifier,
		uint8(inStartIndex), txr.inCTAUTTokenNum, txr.inPlainAUTTokenNum,
		uint8(outStartIndex), txr.outCTAutTokenNum, txr.outPlainAutTokenNum,
		valueScripts,
		txr.scriptMemo,
		witnessHash,
	)

	packagedAutScript, err := ctautapi.PackageAutScript(autScript)
	if err != nil {
		return nil, fmt.Errorf("fail to package aut script: %v", err)
	}

	tx, err := w.createTransactionMLPByRootSeeds(selectedTxos, abelOutDescs, packagedAutScript, txFee,
		false, abecryptoxkey.PrivacyLevelPSEUDONYMCT, false)
	if err != nil {
		return nil, err
	}
	tx.Tx.AutWitness = autTransferTx.TxWitness

	return tx, nil
}

func (w *Wallet) FindEligibleTxosForCTAUT(scriptType ctautapi.AutScriptType, identifier ctautapi.AutId, targetNumOrValue uint64) ([]*wire.OutPointAbe, error) {
	var err error
	switch scriptType {
	case ctautapi.AutScriptTypeRegistration:
		return nil, nil
	case ctautapi.AutScriptTypeReRegistration:
		fallthrough
	case ctautapi.AutScriptTypeMint:
		var eligibleAUTTokens []*wtxmgr.CTAUTCoin
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
			unspent, _, err := w.TxStore.UnspentOutputsCTAUT(txmgrNs, identifier, true)
			if err != nil {
				return err
			}
			eligibleAUTTokens = make([]*wtxmgr.CTAUTCoin, 0, len(unspent))
			for i := range unspent {
				output := unspent[i]

				if output.Spent {
					continue
				}

				eligibleAUTTokens = append(eligibleAUTTokens, output)
			}
			return err
		})
		if err != nil {
			return nil, err
		}

		outpoints := make([]*wire.OutPointAbe, 0, targetNumOrValue)
		addrKeyMap := make(map[string]struct{})
		for i := 0; i < len(eligibleAUTTokens); i++ {
			if uint64(len(outpoints)) > targetNumOrValue {
				break
			}
			if !eligibleAUTTokens[i].IsAUTRootCoin {
				continue
			}
			if _, ok := addrKeyMap[hex.EncodeToString(eligibleAUTTokens[i].AddrKey)]; ok {
				continue
			}
			addrKeyMap[hex.EncodeToString(eligibleAUTTokens[i].AddrKey)] = struct{}{}
			outpoint := &wire.OutPointAbe{
				TxHash: eligibleAUTTokens[i].TxOutput.TxHash,
				Index:  eligibleAUTTokens[i].TxOutput.Index,
			}
			outpoints = append(outpoints, outpoint)
		}
		if len(outpoints) < int(targetNumOrValue) {
			return nil, errors.New("not enough root coin to re-register/mint")
		}
		return outpoints, nil

	case ctautapi.AutScriptTypeTransfer:
		fallthrough
	case ctautapi.AutScriptTypeBurn:
		var eligibleAUTTokens []*wtxmgr.CTAUTCoin
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
			unspent, _, err := w.TxStore.UnspentOutputsCTAUT(txmgrNs, identifier, false)
			if err != nil {
				return err
			}
			eligibleAUTTokens = make([]*wtxmgr.CTAUTCoin, 0, len(unspent))
			for i := range unspent {
				output := unspent[i]

				if output.Spent {
					continue
				}

				eligibleAUTTokens = append(eligibleAUTTokens, output)
			}
			return err
		})
		if err != nil {
			return nil, err
		}

		outpoints := make([]*wire.OutPointAbe, 0, 100)
		addrKeyMap := make(map[string]struct{})
		totalValue := uint64(0)
		for i := 0; i < len(eligibleAUTTokens); i++ {
			if totalValue >= targetNumOrValue {
				break
			}
			if eligibleAUTTokens[i].IsAUTRootCoin {
				continue
			}
			totalValue += eligibleAUTTokens[i].Value
			if _, ok := addrKeyMap[hex.EncodeToString(eligibleAUTTokens[i].AddrKey)]; ok {
				continue
			}
			addrKeyMap[hex.EncodeToString(eligibleAUTTokens[i].AddrKey)] = struct{}{}
			outpoint := &wire.OutPointAbe{
				TxHash: eligibleAUTTokens[i].TxOutput.TxHash,
				Index:  eligibleAUTTokens[i].TxOutput.Index,
			}
			outpoints = append(outpoints, outpoint)
		}
		if totalValue < targetNumOrValue {
			return nil, errors.New("not enough token to transfer/burn")
		}
		return outpoints, nil
	default:
		return nil, errors.New("unsupported ct-aut type")
	}
}

func (w *Wallet) findEligibleTxosAbeCTAUT(txmgrNs walletdb.ReadBucket, minconf int32, bs *waddrmgr.BlockStamp, identifier ctautapi.AutId) ([]*wtxmgr.CTAUTCoin, error) {
	unspent, _, err := w.TxStore.UnspentOutputsCTAUT(txmgrNs, identifier, false) // In ABE, this result will be spendable for the logic of store
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]*wtxmgr.CTAUTCoin, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		if output.Spent {
			continue
		}

		eligible = append(eligible, output)
	}
	return eligible, nil
}
