package main

import (
	"fmt"

	"github.com/sem-hub/snake-net/internal/crypt/engines"
)

func init() {
}

func main() {
	for _, engine := range engines.EnginesList {
		fmt.Println("Benchmarking engine:", engine)
	}
	for mode := range engines.ModesList {
		fmt.Println("Benchmarking mode:", mode)
	}
}
