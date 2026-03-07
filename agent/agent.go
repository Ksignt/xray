package agent

/*
#cgo CFLAGS: -I../tracer
#cgo LDFLAGS: -L../tracer -ltcp_to_pid_user -lbpf
#include "../tracer/tcp_to_pid_user.h"
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
	fmt.Printf("Attaching Listners...\n")

	fmt.Printf("Attaching tcp_recvmsg Listner\n")
	load_tcp_recvmsg_status := C.load_tcp_recv_listener(C.int(pid))
	fmt.Printf("PID: %d\n", pid)

	if load_tcp_recvmsg_status != 0 {
		fmt.Printf("Failed to load tcp_recvmsg listener\n")
	} else {
		fmt.Printf("Successfully loaded tcp_recvmsg listener\n")
	}
}
