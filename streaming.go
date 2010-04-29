package main

import (
    "http"
    "net"
    "os"
    "time"
)

type Server struct {
    addr string
}

func (s *Server) handleRequest(req *http.Request) (*http.Response, os.Error) {
    resp := http.Response{
        StatusCode:    200,
        RequestMethod: req.Method,
        ProtoMajor:    1,
        ProtoMinor:    1,
        Close:         false,
    }

    return &resp, nil
}

func (s *Server) handleConn(conn net.Conn) {
    for {
        sc := http.NewServerConn(conn, nil)
        req, err := sc.Read()
        if err != nil {
            println("read error", err.String())
            break
        }
        resp, err := s.handleRequest(req)
        if err != nil {
            println("handle error", err.String())
            break
        }

        err = sc.Write(resp)
        if err != nil {
            println("write error", err.String())
            break
        }

        for {
            conn.Write([]byte("hello\n"))
            time.Sleep(5e9)
        }
    }
}

func (s *Server) Serve(l net.Listener) os.Error {
    for {
        conn, e := l.Accept()
        if e != nil {
            return e
        }

        go s.handleConn(conn)
    }
    panic("not reached")
}

func (s *Server) Run(addr string) os.Error {
    l, e := net.Listen("tcp", addr)
    if e != nil {
        return e
    }
    e = s.Serve(l)
    l.Close()
    return e
}

func main() {
    var server Server
    server.Run("127.0.0.1:9999")
    <-make(chan int)
}
