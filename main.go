package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

type Conta struct {
	Account string
	PvtKey  string
	Valid   bool
}

const PREFIX_NAME = "MARTHAGABRIEL"

var keyNames map[string]Conta

var CHARACTERS = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func init() {
	keyNames = make(map[string]Conta)
	rand.Seed(time.Now().UnixNano())
}

func main() {
	fmt.Printf("\n\n\n")

	err := randomNameGenerator(PREFIX_NAME, keyNames, 10)
	if err != nil {
		log.Fatalf("\n%s\n", err.Error())
		return
	}

	for keyStr, conta := range keyNames {
		newConta, err := generateEtheremKey(keyStr, conta)
		if err != nil {
			log.Fatalf("\n%s\n", err.Error())
			return
		}
		keyNames[keyStr] = newConta
		fmt.Println(keyStr, keyNames[keyStr])
	}
}

func generateEtheremKey(privateKey string, conta Conta) (newConta Conta, err error) {
	if len(privateKey) != 32 {
		err = fmt.Errorf("private key invalid. Length: %d", len(privateKey))
		return
	}
	privateKeyHex := hex.EncodeToString([]byte(privateKey))
	privateKeyHexECDSA, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return
	}
	publicKey := privateKeyHexECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		err = errors.New("it was not possible to cast public key to ECDSA format")
		return
	}
	newConta.Account = crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	newConta.PvtKey = privateKeyHex
	newConta.Valid = true
	return
}

func randomNameGenerator(name string, nameList map[string]Conta, totalItems int) (err error) {
	if totalItems > 999 {
		err = errors.New("above total item limits")
		return
	}
	strLen := len(name)
	if strLen > 32 {
		err = errors.New("above allowed characters length")
		return
	}
	var idx int
	for z := 1; z <= totalItems; z++ {
		var newKey strings.Builder
		for i := 0; i < strLen; i++ {
			idx = rand.Intn(strLen)
			newKey.WriteString(name[idx : idx+1])
		}
		newKey.WriteString(time.Now().Format("20060102150405"))
		if len(newKey.String()) < 29 {
			missingChar := 29 - len(newKey.String())
			newKey.WriteString(randSeq(missingChar))
		}
		newKey.WriteString(fmt.Sprintf("%03d", z))
		if nameList[newKey.String()].Valid {
			z--
			continue
		} else {
			nameList[newKey.String()] = Conta{Valid: true}
		}
	}
	return
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = CHARACTERS[rand.Intn(len(CHARACTERS))]
	}
	return string(b)
}
