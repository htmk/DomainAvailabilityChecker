package main

import (
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"github.com/likexian/whois-go"
	whoisParser "github.com/likexian/whois-parser-go"
	"github.com/mattn/go-isatty"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"sync"
)

const (
	loading = iota
	available
	unavailable
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./DomainAvailabilityChecker <domain name> [number of tlds to check, default = 10]")
		return
	}

	input := os.Args[1]

	tldnum := 10
	if len(os.Args) == 3 {
		tldnum, _ = strconv.Atoi(os.Args[2])
	}
	tlds := make([]string,int(tldnum))

	list, err := ioutil.ReadFile("tldlist")

	if err != nil {
		tlds = []string{"com","net","org","co","xyz","info","io","me","top","in"}
		//panic(err)
	}else{
		split := bytes.Split(list, []byte("\n"))
		if tldnum > len(split){
			tldnum = len(split)
		}
		for i := 0; i < tldnum; i++ {
			tlds[i] = string(split[i])
		}
	}
	endOnly := false
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		endOnly = true
	}
	//fmt.Print(string(list))

	var state sync.Map
	for _, tld := range tlds {
		state.Store(tld, loading)
	}

	hasPrintedState := false

	mutex := &sync.Mutex{}

	printState := func() {
		mutex.Lock()
		if hasPrintedState {
			fmt.Printf("\033[%vF", len(tlds))
		} else {
			hasPrintedState = true
		}

		for _, tld := range tlds {
			name := input + "." + tld
			line := name + ": "
			value, _ := state.Load(tld)
			switch value {
			case available:
				line += color.GreenString("Available")
			case unavailable:
				line += color.RedString("Unavailable")
			}
			fmt.Println(line)
		}
		mutex.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(len(tlds) * 2)

	for i := range tlds {
		tld := tlds[i]
		name := input + "." + tld

		go func() {
			defer wg.Done()
			_, err := net.LookupHost(name)
			if err == nil {
				state.Store(tld, unavailable)
				if !endOnly {
					printState()
				}
			}
		}()

		go func() {
			defer wg.Done()
			rawResult, _ := whois.Whois(name)
			result, err := whoisParser.Parse(rawResult)
			if err == nil {
				if result.Registrar.DomainStatus != "" {
					state.Store(tld, unavailable)
					if !endOnly{
						printState()
					}
				} else {
					state.Store(tld, available)
					if !endOnly{
						printState()
					}
				}
			}
		}()
	}

	wg.Wait()

	if endOnly{
		printState()
	}
}
