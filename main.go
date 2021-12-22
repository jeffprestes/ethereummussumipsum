package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
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

const (
	PREFIX_NAME        = "MARTHAGABRIEL"
	TOTAL_ACCOUNTS     = 250
	GOOGLESHEET_OR_CSV = "googlesheet"
)

var keyNames map[string]ReceiverAccount

var CHARACTERS = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func init() {
	keyNames = make(map[string]ReceiverAccount)
	rand.Seed(time.Now().UnixNano())
}

func main() {
	fmt.Printf("\n\nGenerating private keys...\n")
	err := randomNameGenerator(PREFIX_NAME, keyNames, TOTAL_ACCOUNTS)
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

	if GOOGLESHEET_OR_CSV == "googlesheet" {
		fmt.Printf("\n\nUpdating google spreadsheet with with data...\n")
		err = generateGoogleSpreadsheet(keyNames, "1wp0_QaEJBITXUoYnLw2jTwFxe6pCk9GHP6zWLoDPCcI", "teste", TOTAL_ACCOUNTS)
		if err != nil {
			log.Fatalf("\n%s\n", err.Error())
			return
		}
		fmt.Printf("\n\nSpreadsheet updated!\n\n")
	} else {
		fmt.Printf("\n\nGenerating CSV file with data...\n")
		err = generateCSVFile(keyNames, "./giftedkeys.csv")
		if err != nil {
			log.Fatalln("Error generating keys...", err.Error())
		}
		fmt.Printf("\n\nFile generated!\n\n")
	}
}

func generateGoogleSpreadsheet(source map[string]ReceiverAccount, sheetFileID, sheetID string, totalAccounts int) (err error) {
	ctx := context.Background()
	credFile, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		return err
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(credFile, "https://www.googleapis.com/auth/spreadsheets")
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)

	srv, err := sheets.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return err
	}
	totalAccounts++
	cellRange := sheetID + "!I2:J" + strconv.Itoa(totalAccounts)
	var vr sheets.ValueRange
	for _, acct := range source {
		var cellValue []interface{}
		cellValue = append(cellValue, acct.EthereumAddress)
		cellValue = append(cellValue, acct.PvtKey)
		vr.Values = append(vr.Values, cellValue)
	}
	_, err = srv.Spreadsheets.Values.Update(sheetFileID, cellRange, &vr).ValueInputOption("RAW").Do()
	if err != nil {
		return err
	}

	// https://dev.to/afrocoder/playing-with-google-sheets-api-using-golang-14en
	// Following this example: https://developers.google.com/sheets/api/quickstart/go
	// Prints the names and majors of students in a sample spreadsheet:
	// https://docs.google.com/spreadsheets/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit
	// spreadsheetId := "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"
	// readRange := sheetID + "!A1:A4"
	// resp, err := srv.Spreadsheets.Values.Get(sheetFileID, readRange).Do()
	// if err != nil {
	// 	return
	// }

	// if len(resp.Values) == 0 {
	// 	fmt.Println("No data found.")
	// } else {
	// 	for _, row := range resp.Values {
	// 		// Print line .
	// 		fmt.Printf("%s\n", row[0])
	// 	}
	// }

	return
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

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}
