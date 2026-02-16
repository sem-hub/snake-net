package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"image/color"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/text"
	"gonum.org/v1/plot/vg"
	"gonum.org/v1/plot/vg/draw"

	"github.com/sem-hub/snake-net/internal/configs"
	"github.com/sem-hub/snake-net/internal/crypt"
	"github.com/sem-hub/snake-net/internal/crypt/engines"
	"github.com/sem-hub/snake-net/internal/crypt/signature"
)

var needDraw bool

func init() {
	flag.BoolVar(&needDraw, "draw", false, "Whether to draw the benchmark results.")

}

var password = []byte("32 bytes string for password 123")

type commaTicks struct {
	lines []string
}

func (c commaTicks) Ticks(min, max float64) []plot.Tick {
	var ticks []plot.Tick
	for v := min; v <= max; v++ {
		label := c.lines[int(v)] + "  "
		ticks = append(ticks, plot.Tick{Value: v, Label: label})
	}
	return ticks
}

func drawData(keys []string, medEncrypt map[string]time.Duration, medDecrypt map[string]time.Duration) {
	p := plot.New()
	p.Title.Text = "Chipher Benchmark"
	p.Title.TextStyle.Font.Size = vg.Points(48)
	p.X.Label.Text = "Cipher Engines"
	p.X.Label.TextStyle.Font.Size = vg.Points(36)
	p.X.Tick.Label.Rotation = 1.57
	p.X.Tick.Label.Font.Size = vg.Points(12)
	p.X.Tick.Label.YAlign = text.YCenter
	p.X.Tick.Label.XAlign = text.XRight
	p.X.Tick.Marker = commaTicks{lines: keys}
	p.Y.Label.Text = "Time (microseconds)"
	p.Y.Label.TextStyle.Font.Size = vg.Points(36)
	p.Y.Tick.Label.Font.Size = vg.Points(24)

	p.Add(plotter.NewGrid())
	scatterData := make(plotter.XYs, len(keys))
	scatterData1 := make(plotter.XYs, len(keys))

	for i, name := range keys {
		scatterData[i].X = float64(i)
		scatterData[i].Y = float64(medEncrypt[name].Nanoseconds()) / 1000.0
		scatterData1[i].X = float64(i)
		scatterData1[i].Y = float64(medDecrypt[name].Nanoseconds()) / 1000.0
	}
	s, err := plotter.NewScatter(scatterData)
	if err != nil {
		panic(err)
	}
	s1, err := plotter.NewScatter(scatterData1)
	if err != nil {
		panic(err)
	}
	s.GlyphStyle.Color = color.RGBA{R: 255, G: 128, B: 128, A: 255}
	s1.GlyphStyle.Color = color.RGBA{R: 128, G: 128, B: 255, A: 255}
	s.GlyphStyle.Radius = vg.Points(6)
	s1.GlyphStyle.Radius = vg.Points(6)
	s.GlyphStyle.Shape = draw.CircleGlyph{}
	s1.GlyphStyle.Shape = draw.CircleGlyph{}
	p.Add(s, s1)
	p.Legend.Add("Encrypt time", s)
	p.Legend.Add("Decrypt time", s1)
	p.Legend.TextStyle.Font.Size = vg.Points(24)
	if err := p.Save(36*vg.Inch, 18*vg.Inch, "benchmark_encrypt.png"); err != nil {
		panic(err)
	}
	cmd := exec.Command("xdg-open", "benchmark_encrypt.png")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Error resizing image:", err)
	}
}

func main() {
	flag.Parse()

	// Some initialization
	_ = configs.GetConfigFile()
	_ = configs.GetConfig()
	enginesMap := map[string]engines.CryptoEngine{}
	for _, engineName := range engines.EnginesList {
		size := 256
		engine, err := crypt.CreateEngine(engineName, "cbc", size, password)
		if err != nil {
			size = 128
			engine, err = crypt.CreateEngine(engineName, "cbc", size, password)
			if err != nil {
				continue
			}
		}

		enginesMap[strings.ToLower(engine.GetName())] = engine

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
					}
				}
			}
		}
	}
	keys := []string{}
	for name := range enginesMap {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	// Start benchmarks
	measurements := 1000
	maxEncrypt := map[string]time.Duration{}
	maxDecrypt := map[string]time.Duration{}
	minEncrypt := map[string]time.Duration{}
	minDecrypt := map[string]time.Duration{}
	medEncrypt := map[string]time.Duration{}
	medDecrypt := map[string]time.Duration{}

	for _, engine := range keys {
		fmt.Println("Benchmarking engine:", engine)
		eTime := make([]time.Duration, measurements)
		dTime := make([]time.Duration, measurements)
		for i := range measurements {
			encTime, decTime, err := benchmark(enginesMap[engine], 1240)
			if err != nil {
				fmt.Println("Error benchmarking engine:", engine, ":", err)
				continue
			}
			eTime[i] = encTime
			dTime[i] = decTime
		}
		runtime.GC()

		medEncrypt[engine] = Median(eTime)
		medDecrypt[engine] = Median(dTime)
		maxEncrypt[engine] = time.Duration(0)
		maxDecrypt[engine] = time.Duration(0)
		minEncrypt[engine] = eTime[0]
		minDecrypt[engine] = dTime[0]
		for i := 0; i < measurements; i++ {
			if eTime[i] > maxEncrypt[engine] {
				maxEncrypt[engine] = eTime[i]
			}
			if minEncrypt[engine] > eTime[i] {
				minEncrypt[engine] = eTime[i]
			}
			if minDecrypt[engine] > dTime[i] {
				minDecrypt[engine] = dTime[i]
			}
			if dTime[i] > maxDecrypt[engine] {
				maxDecrypt[engine] = dTime[i]
			}
		}
	}

	// Sort keys
	fmt.Println("Results:")
	fmt.Println("Sorted by encrypt time:")
	sort.Slice(keys, func(i, j int) bool {
		return medEncrypt[keys[i]] < medEncrypt[keys[j]]
	})
	for _, name := range keys {
		fmt.Println("Engine:", name, "encrypt median time:", medEncrypt[name],
			"min:", minEncrypt[name], "max:", maxEncrypt[name],
			"decrypt median time:", medDecrypt[name], "min:", minDecrypt[name],
			"max:", maxDecrypt[name])
	}
	fmt.Println("Sorted by decrypt time:")
	sort.Slice(keys, func(i, j int) bool {
		return medDecrypt[keys[i]] < medDecrypt[keys[j]]
	})
	for _, name := range keys {
		fmt.Println("Engine:", name, "encrypt median time:", medEncrypt[name],
			"min:", minEncrypt[name], "max:", maxEncrypt[name],
			"decrypt median time:", medDecrypt[name], "min:", minDecrypt[name],
			"max:", maxDecrypt[name])
	}

	signatureEngines := make(map[string]signature.SignatureInterface)
	for _, sigName := range signature.SignatureList {
		var err error
		signatureEngines[sigName], err = crypt.CreateSignatureEngine(sigName, password)
		if err != nil {
			fmt.Println("Error creating signature engine:", sigName, ":", err)
			continue
		}
	}
	signatureEngines["ed25519"] = signature.NewSignatureEd25519(password)
	signatureEngines["hmac-sha256"] = signature.NewSignatureHMACSHA256(password)
	signatureEngines["hmac-blake2b"] = signature.NewSignatureHMACBlake(password)

	fmt.Println("Signature Benchmarking:")
	for name, engine := range signatureEngines {
		fmt.Println("Benchmarking signature engine:", name)
		sTime := make([]time.Duration, measurements)
		vTime := make([]time.Duration, measurements)
		for i := range measurements {
			signTime, verifyTime, err := benchmarkSignature(engine, 1240, password)
			if err != nil {
				fmt.Println("Error benchmarking signature engine:", name, ":", err)
				continue
			}
			sTime[i] = signTime
			vTime[i] = verifyTime
		}
		runtime.GC()

		medSign := Median(sTime)
		medVerify := Median(vTime)
		maxSign := time.Duration(0)
		minSign := sTime[0]
		maxVerify := time.Duration(0)
		minVerify := vTime[0]
		for i := 0; i < measurements; i++ {
			if sTime[i] > maxSign {
				maxSign = sTime[i]
			}
			if minSign > sTime[i] {
				minSign = sTime[i]
			}
			if vTime[i] > maxVerify {
				maxVerify = vTime[i]
			}
			if minVerify > vTime[i] {
				minVerify = vTime[i]
			}
		}
		fmt.Println("Signature Engine:", name, "sign median time:", medSign,
			"min:", minSign, "max:", maxSign)
		fmt.Println("Signature Engine:", name, "verify median time:", medVerify,
			"min:", minVerify, "max:", maxVerify)
	}
	if needDraw {
		drawData(keys, medEncrypt, medDecrypt)
	}
}

func Median(durations []time.Duration) time.Duration {
	n := len(durations)
	sorted := make([]time.Duration, n)
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

func benchmark(engine engines.CryptoEngine, dataSize int) (time.Duration, time.Duration, error) {
	data := make([]byte, dataSize)
	_, _ = rand.Read(data)

	debug.SetGCPercent(-1)
	startEnc := time.Now()
	encData, err := engine.Encrypt(data)
	if err != nil {
		return 0, 0, err
	}
	elapsedEnc := time.Since(startEnc)
	debug.SetGCPercent(100)

	debug.SetGCPercent(-1)
	startDec := time.Now()
	_, err = engine.Decrypt(encData)
	if err != nil {
		return 0, 0, err
	}
	elapsedDec := time.Since(startDec)
	debug.SetGCPercent(-1)

	return elapsedEnc, elapsedDec, nil
}

func benchmarkSignature(engine signature.SignatureInterface, dataSize int, password []byte) (time.Duration, time.Duration, error) {
	sessionPublicKey, sessionPrivateKey, err := ed25519.GenerateKey(bytes.NewReader(password))
	if err != nil {
		return 0, 0, errors.New("failed to generate session keys: " + err.Error())
	}
	engine.SetPublicKey(sessionPublicKey)
	engine.SetPrivateKey(sessionPrivateKey)
	data := make([]byte, dataSize)
	_, _ = rand.Read(data)

	debug.SetGCPercent(-1)
	startEnc := time.Now()
	sign := engine.Sign(data)
	elapsedEnc := time.Since(startEnc)
	debug.SetGCPercent(100)

	debug.SetGCPercent(-1)
	startDec := time.Now()

	if !engine.Verify(data, sign) {
		return 0, 0, errors.New("signature verification failed")
	}
	elapsedDec := time.Since(startDec)
	debug.SetGCPercent(-1)

	return elapsedEnc, elapsedDec, nil

}
