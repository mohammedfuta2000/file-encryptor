package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"

	"github.com/xdg-go/pbkdf2"
)

func Encrypt(source string, password []byte) {
	srcFile, err := os.Open(source)
	if err != nil {
		panic("unable to open file")
	}
	defer srcFile.Close()

	plaintext, err := io.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}

	key := password

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	cyphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	cyphertext = append(cyphertext, nonce...)

	dstFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	defer dstFile.Close()

	_, err = dstFile.Write(cyphertext)
	if err != nil {
		panic(err.Error())
	}
}

func Decrypt(source string, password []byte) {
	srcFile, err := os.Open(source)
	if err != nil {
		panic("unable to open file")
	}
	defer srcFile.Close()

	cyphertext, err := io.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}

	key := password

	// salt is nonce
	salt := cyphertext[len(cyphertext)-12:]

	str := hex.EncodeToString(salt)
	nonce, err := hex.DecodeString(str)

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, cyphertext[:len(cyphertext)-12], nil)
	if err != nil {
		panic(err.Error())
	}

	dstFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	defer dstFile.Close()

	_, err = dstFile.Write(plaintext)
	if err != nil {
		panic(err.Error())
	}

}
