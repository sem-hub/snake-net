package main

import (
	"fmt"

	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
}

func main() {
	for _, engineName := range engines.EnginesList {
		fmt.Println("Benchmarking engine:", engineName)
		engine, err := crypt.CreateEngine(engineName, "cbc", 256,
			[]byte("32 bytes string for password 123"))
		if err != nil {
			fmt.Println("Error creating engine:", err)
			continue
		}
		//fmt.Println("engine:", engine.GetName(), "of type:", engine.GetType())

		if engine.GetType() == "block" {
			for mode := range engines.ModesList {
				fmt.Println("Benchmarking mode:", mode)
			}
		}
	}
}
