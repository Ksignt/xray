package agent

/*
#cgo CFLAGS: -I../tracer -I../tracer/utils
#cgo LDFLAGS: -lbpf -lelf -lz
#include "../tracer/utils/loader.c"
#include "../tracer/handlers.c"
#include "../tracer/loader.c"
*/
import "C"

import (
	"fmt"

	rdr "github.com/openObserverbility/trace-graph-engine/configReader"
)

func Run() {
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
	fmt.Printf("Attaching probes...\n")

	status := C.load_probes(C.int(pid))
	if status != 0 {
		fmt.Printf("Failed to load probes\n")
	} else {
		fmt.Printf("Probes exited cleanly\n")
	}
}
