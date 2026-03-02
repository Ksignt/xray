package main

import (
	"fmt"

	rdr "github.com/openObserverbility/trace-graph-engine/configReader"
)

func main() {
	config := rdr.GetConfig("./config.yaml")
	fmt.Printf("Config: %+v\n", config)

	targetBinary, err := rdr.GetTargetBinary(config)
	if err != nil {
		panic(fmt.Sprintf("No TargetBinary config is defined: %v", err))
	}
	fmt.Printf("Target Binary: %s\n", targetBinary)
	pid, err := rdr.GetPidForBinary(targetBinary)
	if err != nil {
		panic(fmt.Sprintf("Error getting PID for target binary: %v", err))
	}
	fmt.Printf("PID: %d\n", pid)
}
