package main

import (
	"net/http"
	//	"os"
	//	"bytes"
	//	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/zxfonline/httplib"
	"github.com/zxfonline/servercore/gerror"
	"github.com/zxfonline/web"
)

type SS struct {
	Name string
	MAP  map[int]*SS
}
type SS1 struct {
	SS
}

//([])(u)int,([])(u)int8,([])(u)int16,([])(u)int32,([])(u)int64,([])float32(64),([])bool,([])byte,string,[]string
func (s *SS) ContextHandle1(ctx *web.Context) (*[]byte, error) {
	var a []byte = []byte{1, 2, 2, 3}
	return &a, nil
}
func (s *SS) ContextHandle2(ctx *web.Context) (bool, error) {
	return true, nil
}
func (s *SS) ContextHandle3(ctx *web.Context) (*[]string, error) {
	var a []string = []string{"s1", "s2", "s3"}
	return &a, nil
}
func (s *SS) ContextHandle4(ctx *web.Context) ([]float32, error) {
	return []float32{1.111, 2.2222, 2.3333, 1.4444}, nil
}
func (s *SS) ContextHandle5(ctx *web.Context) (interface{}, error) {
	ee := gerror.NewError(gerror.OK, "ok")
	//	ee := errors.New("ok----")
	return ee, nil
	//	return nil, nil
}
func (s *SS) ContextHandle(ctx *web.Context) (interface{}, error) {
	//	panic(errors.New("im error"))
	fmt.Println("enter.....")
	s.Name += "1"
	return nil, gerror.NewError(gerror.SERVER_ACCESS_REFUSED, "im gerror")
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
func test1(ctx *web.Context) (interface{}, interface{}) {
	return gerror.NewError(gerror.SERVER_ACCESS_REFUSED, "ok"), "aaaaa"
}
func test(ctx *web.Context, url string) (interface{}, error) {
	//type 1
	//	flusher, _ := ctx.ResponseWriter.(http.Flusher)
	//	//	flusher.Flush()
	//	ctx.WriteString(fmt.Sprintf("receive=%s\n", url))
	//	for k, v := range ctx.Params {
	//		ctx.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	//	}
	//	flusher.Flush()
	//	return nil

	//type 2
	//	bf := bytes.NewBufferString(fmt.Sprintf("receive=%s\n", url))
	//	for k, v := range ctx.Params {
	//		bf.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	//	}
	//	return bf.String()
	//type 3
	//	panic(gerror.NewError(gerror.SERVER_ACCESS_REFUSED, "haha1"))
	//	panic(errors.New("im error"))
	//type 4
	//	return gerror.NewError(gerror.SERVER_ACCESS_REFUSED, "ok")
	//	return gerror.NewError(gerror.SERVER_ACCESS_REFUSED, "ok"), gerror.NewError(gerror.SERVER_ACCESS_REFUSED, "haha")
	return nil, nil
}

func main() {
	wg := &sync.WaitGroup{}
	web.Get("/([0-9]+)", hello)
	//	web.Get("/(*)", hello)
	web.Get("/test/(.*)", test)
	web.Post("/test/(.*)", test)
	s := &SS{Name: "SS"}
	s.MAP = make(map[int]*SS)
	s.MAP[1] = &SS{Name: "map name1"}
	s.MAP[2] = &SS{Name: "map name2"}
	web.Get("/hello", s)
	web.Get("/close", func() {
		web.Close()
		wg.Done()
	})
	//	web.Get("/test1/login", s)
	//http://127.0.0.1:9999/test1/login/aa?name=zxf&pwd=zxf
	web.Get("/test1", web.InvokeService(s, "ContextHandle1"))
	web.Get("/test2", web.InvokeService(s, "ContextHandle2"))
	web.Get("/test3", web.InvokeService(s, "ContextHandle3"))
	web.Get("/test4", web.InvokeService(s, "ContextHandle4"))
	web.Get("/test5", web.InvokeService(s, "ContextHandle5"))

	s1 := &SS1{}
	s1.SS.Name = "ss1"
	s1.MAP = make(map[int]*SS)
	s1.MAP[1] = &SS{Name: "map1 name11"}
	s1.MAP[2] = &SS{Name: "map1 name12"}
	web.Get("/hello1", s1)
	web.Get("/testa", test1)

	wg.Add(1)
	go web.Run("0.0.0.0:9999")
	time.Sleep(1 * time.Second)
	go func() {
		TestSimplePost()
	}()
	wg.Wait()
}

func TestSimplePost() {
	v := "zxf"

	req := httplib.Get("http://127.0.0.1:9999/close")
	req.Param("username", v)

	str, err := req.String()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("str=\n", str)
}
