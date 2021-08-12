package main

import (
	"C"

	bpf "github.com/kubearmor/libbpf"
)
import (
	"fmt"
)

func main() {

	b, err := bpf.OpenObjectFromFile("hello.bpf.o")
	must(err)
	defer b.Close()

	must(b.Load())

	p, err := b.FindProgramByName("hello")
	must(err)

	_, err = p.AttachKprobe("__x64_sys_execve")
	must(err)

	//bpf.TracePrint()

	fmt.Println("Cleaning")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
