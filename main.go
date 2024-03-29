package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fontisAleatoris := rand.NewSource(time.Now().UnixNano())
	aleatorisComoDepoisDeUnsMe := rand.New(fontisAleatoris)
	numerisAletatoris := aleatorisComoDepoisDeUnsMe.Intn(7)

	var chavisDasPrivadis [8]string
	chavisDasPrivadis[0] = "Suco de cevadiss deixa as pessoas mais interessantis"
	chavisDasPrivadis[1] = "Quem manda na minha terra sou euzis!"
	chavisDasPrivadis[2] = "Em pé sem cair, deitado sem dormir, sentado sem cochilar e fazendo pose"
	chavisDasPrivadis[3] = "Manduma pindureta quium dia nois paga"
	chavisDasPrivadis[4] = "Mais vale um bebadis conhecidiss, que um alcoolatra anonimis"
	chavisDasPrivadis[5] = "Interessantiss quisso pudia ce receita de bolis, mais bolis eu num gostis"
	chavisDasPrivadis[6] = "A ordem dos tratores não altera o pão duris"
	chavisDasPrivadis[7] = "Copo furadis é disculpa de bebadis"

	fmt.Printf("\n\n\n")
	fmt.Println("Aê cumpadis, the options are: ")
	for index, cdp := range chavisDasPrivadis {
		fmt.Println("   ", index, cdp)
	}
	fmt.Printf("\n\nThe choosen one is... %d\n\n", numerisAletatoris)

	// privateKey := chavisDasPrivadis[numerisAletatoris][:32]
	privateKey := "PalmeirasTemChanceDeGanharMudial"
	if len(privateKey) != 32 {
		log.Panicln("Private key invalid. Length: ", len(privateKey))
	}
	privateKeyHex := hex.EncodeToString([]byte(privateKey))
	// If you want to get your Public Key from your Metamask or other Ethereum wallet
	// Get your private key from your wallet copy it from your wallet uncomment the line bellow and
	// copy it within the variable
	// privateKeyHex = ""
	privateKeyHexECDSA, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.Fatal("Error getting private key in ECDSA format", err)
	}
	publicKey := privateKeyHexECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("It was not possible to cast public key to ECDSA format")
	}
	publicKeyInBytes := crypto.FromECDSAPub(publicKeyECDSA)
	publicKeyInHex := hexutil.Encode(publicKeyInBytes)
	publicKeyAfterHash := crypto.Keccak256(publicKeyInBytes[1:])
	publicKeyAfterHashString := hexutil.Encode(publicKeyAfterHash)
	yourEthereumAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	fmt.Printf("Cacildis! We have the keys... (BTW, we're using secp256k1 curve and Keccak256 hash algorithim)\n\n")
	fmt.Printf("Private key selected [%s] - It was trimmed because a key must have 32 characters only\n\n", privateKey)
	fmt.Println("Private key in Hexadecimal ", privateKeyHex)
	fmt.Println("")
	fmt.Printf("Private key object ECDSA %+v\n", privateKeyHexECDSA)
	fmt.Println("")
	// fmt.Printf("Public key object %+v\n", publicKey)
	// fmt.Println("")
	fmt.Printf("Public key object ECDSA %+v\n", publicKeyECDSA)
	fmt.Println("")
	fmt.Println("Public Key in Hex ", publicKeyInHex)
	fmt.Println("")
	fmt.Println("Public Key Hash used to generate Ethereum address ", publicKeyAfterHashString)
	fmt.Println("")
	fmt.Println("Your Ethereum address is ", yourEthereumAddress.String())
	fmt.Printf("\nNow publish this text in twitter to poke Vitalik and ask him some ethers: 'Ai, Vitalik gente finis, manda uns ethes pra nois compra uns mé https://etherscan.io/address/%s\n\n", yourEthereumAddress.String())
}
