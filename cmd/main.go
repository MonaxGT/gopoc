package main

import (
	"flag"
	"fmt"
	"gitlab.com/rt-cert/gopoc"
)

func main() {
	modePtr := flag.Bool("v", false, "Verbose mode")
	filePtr := flag.String("f", "", "Yaml file")
	flag.Parse()
	fmt.Println(gopoc.Check(*filePtr, *modePtr))

}
