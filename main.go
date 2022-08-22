package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Set to 0 to find game automatically
var pid = 0

func runInstruction(instr []byte, rcx uint64) {
	// Get old registers
	var oldRegs syscall.PtraceRegs
	syscall.PtraceGetRegs(pid, &oldRegs)

	// Get old (partial) instruction at the address
	oldInstr := make([]byte, len(instr))
	syscall.PtracePeekData(pid, uintptr(oldRegs.Rip), oldInstr)

	// Replace with new instruction & registers
	syscall.PtracePokeData(pid, uintptr(oldRegs.Rip), instr)

	var newRegs syscall.PtraceRegs
	syscall.PtraceGetRegs(pid, &newRegs)
	newRegs.Rcx = rcx
	syscall.PtraceSetRegs(pid, &newRegs)

	// Step
	syscall.PtraceSingleStep(pid)
	var status syscall.WaitStatus
	syscall.Wait4(pid, &status, 0, nil)
	if !status.Stopped() || status.StopSignal() != 5 {
		panic("woops")
	}

	// Replace with old instruction & registers
	syscall.PtracePokeData(pid, uintptr(oldRegs.Rip), oldInstr)
	syscall.PtraceSetRegs(pid, &oldRegs)
}

func trapAndListen(funcStart uintptr) {
	// Attach to process
	syscall.PtraceAttach(pid)
	var status syscall.WaitStatus
	syscall.Wait4(pid, &status, 0, nil)
	if status.Stopped() && status.StopSignal() == 19 {
		fmt.Println("ptrace has attached")
	} else {
		panic("woops")
	}

	// Get old (partial) instructions at the addresses
	oldInstr1 := make([]byte, 1)
	syscall.PtracePeekData(pid, funcStart, oldInstr1)
	oldInstr2 := make([]byte, 1)
	syscall.PtracePeekData(pid, funcStart+0x73, oldInstr2)

	// Replace instructions with breakpoints
	syscall.PtracePokeData(pid, funcStart, []byte{0xcc})
	syscall.PtracePokeData(pid, funcStart+0x73, []byte{0xcc})

	// Continue running
	syscall.PtraceCont(pid, 0)

	for {
		// Wait for a trap
		syscall.Wait4(pid, &status, 0, nil)
		if status.StopSignal() != 5 {
			if status.Stopped() {
				syscall.PtraceCont(pid, int(status.StopSignal()))
			}

			continue
		}

		fmt.Println("trapped fov call")

		// Get current regs
		var regs syscall.PtraceRegs
		syscall.PtraceGetRegs(pid, &regs)

		// Save rcx
		passedRcx := regs.Rcx
		fmt.Printf("captured rcx: %x\n", passedRcx)

		// Add the old instruction back & rewind the ip
		fmt.Println("rewinding instruction pointer")
		syscall.PtracePokeData(pid, funcStart, oldInstr1)
		regs.Rip = uint64(funcStart)
		syscall.PtraceSetRegs(pid, &regs)

		// Step the old instruction
		syscall.PtraceSingleStep(pid)
		var status syscall.WaitStatus
		syscall.Wait4(pid, &status, 0, nil)
		if !status.Stopped() || status.StopSignal() != 5 {
			panic("woops")
		}

		// Put the breakpoint back
		syscall.PtracePokeData(pid, funcStart, []byte{0xcc})

		// Continue execution to the breakpoint at the end of the function
		fmt.Println("continuing to end of function")
		syscall.PtraceCont(pid, 0)
		syscall.Wait4(pid, &status, 0, nil)
		if !status.Stopped() || status.StopSignal() != 5 {
			panic("woops")
		}

		// Run instruction to update fov at [rcx+0x40]
		instr := bytes.NewBuffer([]byte{0xc7, 0x41, 0x40})
		binary.Write(instr, binary.LittleEndian, float32(120.0)/float32(78.0))

		fmt.Println("running instr:", hex.EncodeToString(instr.Bytes()))
		runInstruction(instr.Bytes(), passedRcx)

		// Add the old instruction back & rewind the ip
		fmt.Println("rewinding instruction pointer again")
		syscall.PtracePokeData(pid, funcStart+0x73, oldInstr2)
		syscall.PtraceGetRegs(pid, &regs)
		regs.Rip = uint64(funcStart + 0x73)
		syscall.PtraceSetRegs(pid, &regs)

		// Step the old instruction
		syscall.PtraceSingleStep(pid)
		syscall.Wait4(pid, &status, 0, nil)
		if !status.Stopped() || status.StopSignal() != 5 {
			panic("woops")
		}

		// Put the breakpoint back
		syscall.PtracePokeData(pid, funcStart+0x73, []byte{0xcc})

		fmt.Println("done")

		// Stop the process so gdb can be attached
		syscall.PtraceCont(pid, 0)

	}
}

func findProcess() int {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		panic(err)
	}

	for _, v := range procs {
		if !v.IsDir() {
			continue
		}

		f, err := os.Open("/proc/" + v.Name() + "/cmdline")
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			panic(err)
		}

		b, err := io.ReadAll(f)
		if err != nil {
			panic(err)
		}
		f.Close()

		if strings.Contains(string(b), "SoTGame.exe") && !strings.Contains(string(b), "steam.exe") && !strings.Contains(string(b), "waitforexitandrun") {
			pid, err := strconv.Atoi(string(v.Name()))
			if err != nil {
				panic(err)
			}

			return pid
		}
	}

	panic("couldn't find pid for game. try setting it manually.")
}

func main() {
	if pid == 0 {
		pid = findProcess()
		fmt.Println("found pid:", pid)
	}

	// Open memory
	fmt.Println("scanning memory")
	mem, err := os.Open(fmt.Sprintf("/proc/%v/mem", pid))
	if err != nil {
		panic(err)
	}
	defer mem.Close()

	// Open map
	procMap, err := os.Open(fmt.Sprintf("/proc/%v/maps", pid))
	if err != nil {
		panic(err)
	}
	defer procMap.Close()

	// Search through each block in map
	scanner := bufio.NewScanner(procMap)
	for scanner.Scan() {
		// Split on spaces to find addr range
		split := strings.Split(scanner.Text(), " ")
		if split[0] == "ffffffffff600000-ffffffffff601000" {
			continue
		} else if !strings.Contains(split[1], "r") {
			continue
		}

		// Split range to find start and end
		split = strings.Split(split[0], "-")
		start, err := strconv.ParseInt(split[0], 16, 64)
		if err != nil {
			panic(err)
		}
		end, err := strconv.ParseInt(split[1], 16, 64)
		if err != nil {
			panic(err)
		}

		// Read range from memory
		b := make([]byte, int(end-start))
		_, err = mem.Seek(start, io.SeekStart)
		if err != nil {
			panic(err)
		}
		_, err = mem.Read(b)
		if err != nil {
			fmt.Println(err)
		}

		// Search for pattern
		i := bytes.Index(b, []byte{0x40, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x80, 0x79, 0x44, 0x00})
		if i != -1 {
			fmt.Printf("found func at: %x\n", int(start)+i)
			trapAndListen(uintptr(int(start) + i))
		}
	}
}
