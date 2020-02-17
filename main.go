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
		log.Fatal("Please provide a prowler output file (from -M json) as the first argument")
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

	scored := make([]checkResult, 0)
	unscored := make([]checkResult, 0)

	for _, r := range checkResults {
		if r.Status == "Fail" {
			if r.Scored == "Scored" {
				scored = append(scored, r)
			} else {
				unscored = append(unscored, r)
			}
		}
	}

	log.Printf("%d checks in total\n", len(checkResults))
	failureTotal := len(scored) + len(unscored)
	percent := int(float32(failureTotal) / float32(len(checkResults)) * 100)
	log.Printf("%d failures (roughly %d percent)\n", failureTotal, percent)

	log.Print("\nScored Fails\n============\n\n")
	for _, r := range scored {
		fmt.Printf("%s\n%s - %s\n%s\n\n", r.Control, r.ControlID, r.Level, r.Message)
	}

	log.Print("\nUnscored Fails\n==============\n\n")
	for _, r := range unscored {
		fmt.Printf("%s\n%s - %s\n%s\n\n", r.Control, r.ControlID, r.Level, r.Message)
	}
}
