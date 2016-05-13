package main

import (
	"net/http"
	//	"os"
	"strconv"
	"time"

	"github.com/zxfonline/web"
)

type SS struct {
	Name string
	MAP  map[int]*SS
}
type SS1 struct {
	SS
}

func (s *SS) ContextHandle(ctx *web.Context) (interface{}, error) {
	s.Name += "1"
	return s, nil
}
func (s *SS1) ContextHandle(ctx *web.Context) (interface{}, error) {
	return s.SS.ContextHandle(ctx)
}
func hello(ctx *web.Context, num string) {
	flusher, _ := ctx.ResponseWriter.(http.Flusher)
	flusher.Flush()
	n, _ := strconv.ParseInt(num, 10, 64)
	for i := int64(0); i < n; i++ {
		ctx.WriteString("<br>hello world</br>")
		flusher.Flush()
		time.Sleep(1e9)
	}
}

func main() {
	web.Get("/([0-9]+)", hello)
	s := &SS{Name: "SS"}
	s.MAP = make(map[int]*SS)
	s.MAP[1] = &SS{Name: "map name1"}
	s.MAP[2] = &SS{Name: "map name2"}
	web.Get("/hello", s)
	web.Get("/close", func() {
		web.Close()
	})

	s1 := &SS1{}
	s1.SS.Name = "ss1"
	s1.MAP = make(map[int]*SS)
	s1.MAP[1] = &SS{Name: "map1 name11"}
	s1.MAP[2] = &SS{Name: "map1 name12"}
	web.Get("/hello1", s1)
	web.Run("0.0.0.0:9999")
}
