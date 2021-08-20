package main

import (
	"C"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
import (
	"os"
	"os/signal"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	b, err := bpf.NewModuleFromFile("hello.bpf.o")
	must(err)
	defer b.Close()

	err = b.BPFLoadObject()
	must(err)

	prog, err := b.GetProgram("hello")
	must(err)
	_, err = prog.AttachKprobe(sys_execve)
	must(err)

	sub_prog, err := b.GetProgram("world")
	must(err)
	sub_prog_fd := sub_prog.GetFd()

	prog_map, err := b.GetMap("jmp_table")
	must(err)

	err = prog_map.Update(sub1_prog_index, uint32(sub_prog_fd))
	must(err)

	go bpf.TracePrint()

	<-sig
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
