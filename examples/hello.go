package main

import (
	"fmt"

	"github.com/zxfonline/strutil"
	"github.com/zxfonline/web"
)

func hello(val string, val1 string) string {

	return fmt.Sprintf("hello %v-> %v | %v-> %v ", val, strutil.Stoi(val, 0), val1, strutil.Stoi(val1, 0))
}

func main() {
	web.Get(`/hello/(-?[1-9]\d*)/([1-9]\d*)`, hello)
	web.Get("/close", func() {
		web.Close()
	})
	fmt.Println(web.Run("0.0.0.0:9999"))
}
