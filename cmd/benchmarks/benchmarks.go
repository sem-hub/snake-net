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
	encryptTime := map[string][]time.Duration{}
	decryptTime := map[string][]time.Duration{}
	plaintext := make([]byte, 1420)
	measurements := 1000
	chipherText := make([][]byte, measurements)
	for engine := range enginesMap {
		fmt.Println("Benchmarking engine:", engine)
		encryptTime[engine] = make([]time.Duration, measurements)
		decryptTime[engine] = make([]time.Duration, measurements)
		for i := range measurements {
			rand.Read(plaintext)
			chipherText[i] = make([]byte, len(plaintext))

			start := time.Now()
			var err error
			chipherText[i], err = enginesMap[engine].Encrypt(plaintext)
			elapsed := time.Since(start)
			if err != nil {
				fmt.Println("Error encrypting with engine", engine, ":", err)
				continue
			}
			encryptTime[engine][i] = elapsed
		}
		for i := range measurements {
			start := time.Now()
			_, err := enginesMap[engine].Decrypt(chipherText[i])
			elapsed := time.Since(start)
			if err != nil {
				fmt.Println("Error decrypting with engine", engine, ":", err)
				continue
			}
			decryptTime[engine][i] = elapsed
		}
	}
	// Sort keys
	sort.Strings(keys)
	fmt.Println("Results:")
	byEncrypt := map[string]time.Duration{}
	byDecrypt := map[string]time.Duration{}
	for _, name := range keys {
		//fmt.Println("Engine:", name, "encrypt time:", encryptTime[name], "decrypt time:", decryptTime[name], "(mode):", enginesMap[name].GetType())

		for _, t := range encryptTime[name] {
			byEncrypt[name] += t
		}
		for _, t := range decryptTime[name] {
			byDecrypt[name] += t
		}
		byEncrypt[name] /= time.Duration(measurements)
		byDecrypt[name] /= time.Duration(measurements)
	}
	fmt.Println("Sorted by encrypt time:")
	sort.Slice(keys, func(i, j int) bool {
		return byEncrypt[keys[i]] < byEncrypt[keys[j]]
	})
	for _, name := range keys {
		fmt.Println("Engine:", name, "encrypt time:", byEncrypt[name], "decrypt time:", byDecrypt[name], "(mode):", enginesMap[name].GetType())
	}
	fmt.Println("Sorted by decrypt time:")
	sort.Slice(keys, func(i, j int) bool {
		return byDecrypt[keys[i]] < byDecrypt[keys[j]]
	})
	for _, name := range keys {
		fmt.Println("Engine:", name, "encrypt time:", byEncrypt[name], "decrypt time:", byDecrypt[name], "(mode):", enginesMap[name].GetType())
	}

}
