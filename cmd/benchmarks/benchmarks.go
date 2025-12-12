package main

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
}

var password = []byte("32 bytes string for password 123")

func main() {
	_ = configs.GetConfigFile()
	_ = configs.GetConfig()
	enginesMap := map[string]engines.CryptoEngine{}
	for _, engineName := range engines.EnginesList {
		//fmt.Println("Benchmarking engine:", engineName)
		size := 256
		engine, err := crypt.CreateEngine(engineName, "cbc", size, password)
		if err != nil {
			size = 128
			engine, err = crypt.CreateEngine(engineName, "cbc", size, password)
			if err != nil {
				//fmt.Println("Error creating engine:", err)
				continue
			}
		}

		enginesMap[strings.ToLower(engine.GetName())] = engine

		//fmt.Println("engine:", engine.GetName(), "of type:", engine.GetType(), "allowed sizes:", engine.GetKeySizes())
		//fmt.Println("engine:", engine.GetName())
		if engine.GetType() == "block" {
			for mode := range engines.ModesList {
				for _, size = range engine.GetKeySizes() {
					if _, ok := enginesMap[engineName+"-"+strconv.Itoa(size)+"-"+mode]; !ok {
						//fmt.Println("Creating", engineName, "with mode", mode, "and size", size)
						engine1, err := crypt.CreateEngine(engineName, mode, size, password)
						if err != nil {
							//fmt.Println("Error creating engine with mode", mode, ":", err)
							break
						} else {
							enginesMap[strings.ToLower(engine1.GetName())] = engine1
						}
						//fmt.Println("engine:", engine1.GetName())
					}
				}
			}
		}
	}
	keys := []string{}
	for name := range enginesMap {
		keys = append(keys, name)
	}
	// Start benchmarks
	encryptTime := map[string]time.Duration{}
	decryptTime := map[string]time.Duration{}
	plaintext := make([]byte, 1024*1024) // 1 MB of data
	rand.Read(plaintext)
	for engine := range enginesMap {
		fmt.Println("Benchmarking engine:", engine)
		start := time.Now()
		chipherText, err := enginesMap[engine].Encrypt(plaintext)
		elapsed := time.Since(start)
		if err != nil {
			fmt.Println("Error encrypting with engine", engine, ":", err)
			continue
		}
		encryptTime[engine] = elapsed
		start = time.Now()
		_, err = enginesMap[engine].Decrypt(chipherText)
		elapsed = time.Since(start)
		if err != nil {
			fmt.Println("Error decrypting with engine", engine, ":", err)
			continue
		}
		decryptTime[engine] = elapsed
	}
	// Sort keys
	sort.Strings(keys)
	fmt.Println("Results:")
	byEncrypt := make([]time.Duration, len(keys))
	byDecrypt := make([]time.Duration, len(keys))
	for i, name := range keys {
		fmt.Println("Engine:", name, "encrypt time:", encryptTime[name], "decrypt time:", decryptTime[name], "(mode):", enginesMap[name].GetType())

		byEncrypt[i] = encryptTime[name]
		byDecrypt[i] = decryptTime[name]
	}
	fmt.Println("Sorted by encrypt time:")
	sort.Slice(keys, func(i, j int) bool {
		return encryptTime[keys[i]] < encryptTime[keys[j]]
	})
	for _, name := range keys {
		fmt.Println("Engine:", name, "encrypt time:", encryptTime[name], "decrypt time:", decryptTime[name], "(mode):", enginesMap[name].GetType())
	}
	fmt.Println("Sorted by decrypt time:")
	sort.Slice(keys, func(i, j int) bool {
		return decryptTime[keys[i]] < decryptTime[keys[j]]
	})
	for _, name := range keys {
		fmt.Println("Engine:", name, "encrypt time:", encryptTime[name], "decrypt time:", decryptTime[name], "(mode):", enginesMap[name].GetType())
	}

}
