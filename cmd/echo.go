package main

import (
	"fmt"

	"github.com/Microsoft/go-winio"
)

func main() {

	laddr := winio.ViosockAddr{Cid: winio.VMADDR_CID_ANY, Port: 8888}
	l, err := winio.ListenViosock(&laddr)
	if err != nil {
		fmt.Println(err)
		panic("failed to listen")
	}

	fmt.Println("Listen socket created")
	for {
		fmt.Println("Awaiting Connection")
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			panic("failed to accept")
		}
		fmt.Println("Connection Accepted")
		b := make([]byte, 1)
		for {
			n, err := c.Read(b)
			if err != nil {
				fmt.Println(err)
				panic("vsock connection died")
			}
			if n > 0 {
				fmt.Println(err)
				fmt.Print(string(b))
			}
		}
	}
}
