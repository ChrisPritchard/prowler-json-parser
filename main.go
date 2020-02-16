package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type checkResult struct {
	Profile       string
	AccountNumber string `json:"Account Number"`
	Control       string
	Message       string
	Status        string
	Scored        string
	Level         string
	ControlID     string `json:"Control ID"`
	Region        string
	Timestamp     string
}

// Removes the prowler header from the json out, and correctly formats the rest into a json array
func correct(raw []byte) []byte {
	parsed := string(raw)

	start := strings.Index(parsed, "{")
	if start < 2 {
		return raw // likely the input has already been fixed
	}

	result := "[" + strings.Replace(parsed[start:], "}", "},", -1) + "]"
	final := strings.Replace(result, "},\n]", "}]", 1)
	return []byte(final)
}

func main() {
	log.SetFlags(0) // Disable log timestamp

	if len(os.Args) != 2 {
		fmt.Println("please provide a prowler output file as the first argument")
		os.Exit(1)
	}

	jsonFile, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()

	raw, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal(err)
	}

	raw = correct(raw)

	var checkResults []checkResult
	err = json.Unmarshal(raw, &checkResults)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(checkResults)
}
