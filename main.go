package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0) // Disable log timestamp

	if len(os.Args) != 2 {
		fmt.Println("please provide a prowler output file as the first argument")
		os.Exit(1)
	}

	jsonFile := os.Args[1]

	fmt.Print(jsonFile)
}
