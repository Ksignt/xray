package reader

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
	"gopkg.in/yaml.v3"
)

type Config struct {
	TargetBinary string `yaml:"target_binary"`
}

func GetPidForBinary(binaryPath string) (int, error) {
	procs, err := process.Processes()
	if err != nil {
		return 0, fmt.Errorf("failed to list processes: %v", err)
	}

	var pids []int
	for _, p := range procs {
		cmdline, err := p.Cmdline()
		if err != nil {
			continue
		}

		// Check full path match
		if strings.Contains(cmdline, binaryPath) {
			pids = append(pids, int(p.Pid))
			continue
		}
		// Check basename match + working directory
		if strings.Contains(cmdline, filepath.Base(binaryPath)) {
			cwd, err := p.Cwd()
			if err == nil && cwd == filepath.Dir(binaryPath) {
				pids = append(pids, int(p.Pid))
			}
		}
	}

	if len(pids) == 0 {
		return 0, fmt.Errorf("No running process found for binary: %s", binaryPath)
	}

	if len(pids) > 1 {
		return 0, fmt.Errorf("Multiple processes found for binary: %s, PIDs: %v", binaryPath, pids)
	}

	return pids[0], nil
}

func GetConfig(configPath string) Config {
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		return Config{}
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		panic(fmt.Sprintf("Error parsing config file: %v", err))
	}

	return config

	// fmt.Printf("Target Binary: %s\n", config.TargetBinary)
	// pid, err := getPidForBinary(config.TargetBinary)
	// if err != nil {
	// 	panic(fmt.Sprintf("Error finding PID for binary: %v", err))
	// }
	// fmt.Printf("PID: %d\n", pid)
}

func GetTargetBinary(config Config) (string, error) {
	if config.TargetBinary == "" {
		return "", fmt.Errorf("no target binary specified in config")
	}
	return config.TargetBinary, nil
}
