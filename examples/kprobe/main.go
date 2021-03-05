// This program demonstrates how to attach an eBPF program to a kprobe.
// The program will be attached to the __x64_sys_execve syscall and print out
// the number of times it has been called every second.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 KProbeExample ./bpf/kprobe_example.c

const (
	mapKey uint32 = 0
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		panic(fmt.Errorf("failed to set temporary rlimit: %v", err))
	}

	// Load Program and Map
	specs, err := NewKProbeExampleSpecs()
	if err != nil {
		panic(fmt.Errorf("error while loading specs: %v", err))
	}
	objs, err := specs.Load(nil)
	if err != nil {
		panic(fmt.Errorf("error while loading objects: %v", err))
	}

	// Create and attach __x64_sys_execve kprobe
	closer, err := createAndAttachKProbe("__x64_sys_execve", objs.ProgramKprobeExecve.FD())
	if err != nil {
		panic(fmt.Errorf("create and attach KProbe: %v", err))
	}
	defer closer()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.MapKprobeMap.Lookup(mapKey, &value); err != nil {
				panic(fmt.Errorf("error while reading map: %v", err))
			}
			fmt.Printf("__x64_sys_execve called %d times\n", value)
		case <-stopper:
			return
		}
	}
}

// This function register a new kprobe
func createAndAttachKProbe(funcName string, fd int) (func(), error) {
	attr := unix.PerfEventAttr{
		Type:   0x06, // /sys/bus/event_source/devices/kprobe/type
		Sample: 1,
		Wakeup: 1,
		Ext1:   uint64(uintptr(newStringPointer(funcName))),
	}

	pfd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("unable to open perf events: %w", err)
	}

	if err := attachPerfEvent(pfd, fd); err != nil {
		return nil, err
	}

	return func() {
		_ = syscall.Close(pfd)
	}, nil
}

func attachPerfEvent(pfd, progFd int) error {
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(progFd)); err != 0 {
		return fmt.Errorf("error attaching bpf program to perf event: %w", err)
	}

	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_ENABLE, 0); err != 0 {
		return fmt.Errorf("error enabling perf event: %w", err)
	}

	return nil
}

// TODO: use github.com/cilium/ebpf/internal.NewStringPointer
func newStringPointer(str string) unsafe.Pointer {
	// The kernel expects strings to be zero terminated
	buf := make([]byte, len(str)+1)
	copy(buf, str)

	return unsafe.Pointer(&buf[0])
}
