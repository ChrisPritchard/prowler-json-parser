package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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

	var checkResults []checkResult
	err = json.Unmarshal(raw, &checkResults)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(checkResults)
}
