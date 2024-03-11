package main

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/term"
	"github.com/mohammedfuta2000/file-encryptor/filecrypt"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}
	function := os.Args[1]

	switch function {
	case "help":
		printHelp()
	case "encrypt":
		encryptHandle()
	case "decrypt":
		decryptHandle()
	default:
		fmt.Println("Run encrypt to encrypt a file, decrypt to decrypt and help for instructions")
	}
}

func printHelp() {
	fmt.Println("file encryption")
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tgo run . encrypt /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands: ")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")
}

func encryptHandle() {
	if len(os.Args)<3{
		fmt.Println("Missin the path to file")
		os.Exit(0)
	}
	file:= os.Args[2]
	if !validateFile(file){
		panic("file not found")
	}
	password:=getPassword()
	fmt.Println("\nEncrypting...")
	filecrypt.Encrypt(file,password)
	fmt.Println("\n file succcessfully protected")
}

func decryptHandle() {
	if len(os.Args)<3{
		fmt.Println("Missin the path to file")
		os.Exit(0)
	}
	file:= os.Args[2]
	if !validateFile(file){
		panic("file not found")
	}
	fmt.Println("Enter password: ")
	password,_:=term.ReadPassword(0)
	fmt.Println("\nEncrypting...")
	filecrypt.Decrypt(file,password)
	fmt.Println("\n file succcessfully decrypted")
}

func getPassword() []byte {
	fmt.Println("Please enter password")
	password,_:=term.ReadPassword(0)
	fmt.Println("\nconfirm password: ")
	password2,_:=term.ReadPassword(0)
	if !validatePassword(password,password2){
		fmt.Println("passwords do not match. please try again")
		return getPassword()
	}
	return password
}

func validatePassword(p1,p2 []byte)bool {
	if !bytes.Equal(p1,p2){
		return false
	}
	return true
}

func validateFile(file string) bool{
	if _,err:=os.Stat(file); os.IsNotExist(err){
		return false
	}
	return true
}
