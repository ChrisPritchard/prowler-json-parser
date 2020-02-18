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

func writeCsv(fileName string, results []checkResult) {
	csv := ""
	for _, r := range results {
		csv += fmt.Sprintf("%s,%s,%s,%s\n", r.Control, r.ControlID, r.Level, r.Message)
	}
	ioutil.WriteFile(fileName, []byte(csv), 0644)
}

func printOutput(totalLength int, scored []checkResult, unscored []checkResult) {
	log.Printf("%d checks in total\n", totalLength)
	failureTotal := len(scored) + len(unscored)
	percent := int(float32(failureTotal) / float32(totalLength) * 100)
	log.Printf("%d failures (roughly %d percent)\n", failureTotal, percent)

	log.Print("\nScored Fails\n============\n\n")
	for _, r := range scored {
		log.Printf("%s\n%s - %s\n%s\n\n", r.Control, r.ControlID, r.Level, r.Message)
	}

	log.Print("\nUnscored Fails\n==============\n\n")
	for _, r := range unscored {
		log.Printf("%s\n%s - %s\n%s\n\n", r.Control, r.ControlID, r.Level, r.Message)
	}
}

func main() {
	log.SetFlags(0) // Disable log timestamp

	if len(os.Args) == 1 {
		log.Fatal("Please provide a prowler output file (from -M json) as the first argument.\nOptionally pass -p as the second argument to print results instead of writing CSVs.")
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

	if len(os.Args) == 3 && os.Args[2] == "-p" {
		printOutput(len(checkResults), scored, unscored)
	} else {
		writeCsv(os.Args[1]+"-scored.csv", scored)
		writeCsv(os.Args[1]+"-unscored.csv", unscored)
	}
}
