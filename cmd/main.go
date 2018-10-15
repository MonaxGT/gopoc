package main

import (
	"flag"
	"fmt"
	"github.com/MonaxGT/gopoc"
)

func main() {
	modePtr := flag.Bool("v", false, "Verbose mode")
	filePtr := flag.String("f", "", "Yaml file")
	flag.Parse()
	fmt.Println(gopoc.Check(*filePtr, *modePtr))

}
