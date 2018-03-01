package main

import (
	"time"
	"log"
	"fmt"
	"strings"
	"syscall"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"io/ioutil"
	"strconv"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	backendURL     = "https://api.pwnedpasswords.com/range/"
)

func inputPasswd() string {
	fmt.Println("Reminder: This tool does not check password strength!")
    fmt.Print("Type a password to check: ")
    bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
    if err != nil {
		fmt.Println(err)
    }
    password := string(bytePassword)
    return strings.TrimSpace(password)
}

func hashString(value string) string {
	alg := sha1.New()
	alg.Write([]byte(value))
	return strings.ToUpper(hex.EncodeToString(alg.Sum(nil)))
}

func checkPasswd(prefix, suffix string) (isPwned bool, times int) {
	var count int
	resp, err := http.Get(backendURL + prefix)
	if err != nil {
		log.Fatal("Failed to query the Pwned Passwords API")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	results := strings.Split(string(body), "\r\n")
	for _, target := range results {
		if string(target[:35]) == suffix {
			_, err = strconv.ParseInt(target[36:], 10, 64)
			if err != nil {
				fmt.Println(err)
			}
			count, err = strconv.Atoi(strings.Split(target, ":")[1])
			if err != nil {
				fmt.Println(err)
			}
			return true, count
		}
	}
	return false, count
}

func main() {
	passwd := inputPasswd()
	hashedStr := hashString(passwd)
	prefix := strings.ToUpper(hashedStr[:5])
	suffix := strings.ToUpper(hashedStr[5:])
	fmt.Println("Hash prefix: ", prefix)
	fmt.Println("Hash suffix: ", suffix)
	fmt.Println("")
	fmt.Println("Looking up your password...")
	time.Sleep(2 * time.Second)
	isPwned, count := checkPasswd(prefix, suffix)
	if isPwned {
			fmt.Printf("Your password appears in the Pwned Passwords database %v time(s).\n", count)
			if count > 100 {
				fmt.Println("Your password is thoroughly pwned! DO NOT use this password for any reason!")
			} else if count > 20 {
				fmt.Println("Your password is pwned! You should not use this password!")
			} else if count > 0 {
				fmt.Println("Your password is pwned, but not ubiquitous. Use this password at your own risk!")
			} 
	} else {
		fmt.Println("Your password isn't pwned, but that doesn't necessarily mean it's secure!")
	}
}