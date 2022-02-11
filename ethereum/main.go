package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func main() {

	// generate public key pair
	privateKey, _ := crypto.GenerateKey()

	// convert struct privateKey to byte array
	privateKeyBytes := crypto.FromECDSA(privateKey)
	// convert privateKeyBytes to hexstring
	hexPrivateKey := hexutil.Encode(privateKeyBytes)
	// print
	fmt.Printf("Private key:\t %s\n", hexPrivateKey)

	// get public key
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	hexPublicKey := hexutil.Encode(publicKeyBytes)
	fmt.Printf("Public key:\t %s\n", hexPublicKey)

	fmt.Print("\n")
	// CompressPubkey
	compressed := crypto.CompressPubkey(publicKeyECDSA)
	hexCompressed := hexutil.Encode(compressed)
	fmt.Printf("Compress key:\t %s\n", hexCompressed)

	// DecompressPubkey
	decompressed, err := crypto.DecompressPubkey(compressed)
	if err != nil {
		fmt.Printf("Decompress error")
	}
	fmt.Printf("Decompress key:\t %s\n", decompressed)

	fmt.Print("\n")

	// Sign & RecoverPubkey
	pubkey1, seckey := generateKeyPair()
	fmt.Printf("pubkey1:\t %s\n", hexutil.Encode(pubkey1))
	fmt.Printf("seckey:\t %s\n", hexutil.Encode(seckey))

	msg := csprngEntropy(32)
	sig, err := secp256k1.Sign(msg, seckey)
	if err != nil {
		fmt.Printf("Signature error: %s", err)
	}
	fmt.Printf("sig: %s\n", hexutil.Encode(sig))
	pubkey2, err := secp256k1.RecoverPubkey(msg, sig)
	if err != nil {
		fmt.Printf("Recover error: %s", err)
	}
	fmt.Printf("pubkey1:\t %s\n", hexutil.Encode(pubkey2))

	fmt.Print("\n")

	// VerifySignature
	sig2 := sig[:len(sig)-1] // remove recovery id
	if !crypto.VerifySignature(pubkey2, msg, sig2) {
		fmt.Printf("Verify error")
	} else {
		fmt.Println("Verify success")
	}
}

func csprngEntropy(n int) []byte {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	return buf
}

func generateKeyPair() (pubkey, privkey []byte) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey = elliptic.Marshal(secp256k1.S256(), key.X, key.Y)

	privkey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	return pubkey, privkey
}
