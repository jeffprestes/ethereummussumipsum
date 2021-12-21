package main

import (
	"crypto/ecdsa"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

type ReceiverAccount struct {
	EthereumAddress string
	PvtKey          string
	Valid           bool
}

func (ra *ReceiverAccount) toString() (ret []string) {
	ret = append(ret, ra.EthereumAddress)
	ret = append(ret, ra.PvtKey)
	return
}

const PREFIX_NAME = "MARTHAGABRIEL"

var keyNames map[string]ReceiverAccount

var CHARACTERS = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func init() {
	keyNames = make(map[string]ReceiverAccount)
	rand.Seed(time.Now().UnixNano())
}

func main() {
	fmt.Printf("\n\nGenerating private keys...\n")
	err := randomNameGenerator(PREFIX_NAME, keyNames, 10)
	if err != nil {
		log.Fatalf("\n%s\n", err.Error())
		return
	}
	fmt.Printf("\n\nGenerating ethereum addresses...\n")
	for keyStr, conta := range keyNames {
		newConta, err := generateEtheremKey(keyStr, conta)
		if err != nil {
			log.Fatalf("\n%s\n", err.Error())
			return
		}
		keyNames[keyStr] = newConta
		// fmt.Println(keyStr, keyNames[keyStr])
	}
	fmt.Printf("\n\nGenerating CSV file with data...\n")

	err = generateCSVFile(keyNames, "./giftedkeys.csv")
	if err != nil {
		log.Fatalln("Error generating keys...", err.Error())
	}
	log.Println("File generated!")
}

func generateCSVFile(source map[string]ReceiverAccount, filePath string) (err error) {
	err = os.Remove(filePath)
	if err != nil {
		if !strings.Contains(err.Error(), "no such file") {
			return err
		}
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	csvWriter := csv.NewWriter(file)
	// csvWriter.Comma = ';'
	for _, acct := range source {
		csvWriter.Write(acct.toString())
		csvWriter.Flush()
	}
	return
}

func generateEtheremKey(privateKey string, conta ReceiverAccount) (newConta ReceiverAccount, err error) {
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
	newConta.EthereumAddress = crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	newConta.PvtKey = privateKeyHex
	newConta.Valid = true
	return
}

func randomNameGenerator(name string, nameList map[string]ReceiverAccount, totalItems int) (err error) {
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
			nameList[newKey.String()] = ReceiverAccount{Valid: true}
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
