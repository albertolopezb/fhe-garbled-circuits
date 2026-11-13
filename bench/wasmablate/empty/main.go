//go:build js && wasm

// Ablation 1 of 4 for E9: the Go runtime plus syscall/js, nothing else.
package main

import "syscall/js"

func main() {
	js.Global().Set("ablate", js.ValueOf("empty"))
	select {}
}
