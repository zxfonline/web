package web

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"path"
	"reflect"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zxfonline/chanutil"
	"github.com/zxfonline/golog"
	"github.com/zxfonline/json"
	//	"golang.org/x/net/websocket"
)

var HTTP_HEAD = "webserver"

const MAXN_RETRY_TIMES = 60

// ServerConfig is configuration for server objects.
type ServerConfig struct {
	StaticDir    string
	CookieSecret string
	RecoverPanic bool
	Profiler     bool
}

// Server represents a web.go server.
type Server struct {
	Config *ServerConfig
	Logger *golog.Logger
	routes []route
	Env    map[string]interface{}
	//save the listener so it can be closed
	l        net.Listener
	stopD    chanutil.DoneChan
	stopOnce sync.Once
	wg       *sync.WaitGroup
}

func SetStaticDir(StaticDir string) func(*ServerConfig) {
	return func(cfg *ServerConfig) {
		cfg.StaticDir = StaticDir
	}
}
func SetCookieSecret(CookieSecret string) func(*ServerConfig) {
	return func(cfg *ServerConfig) {
		cfg.CookieSecret = CookieSecret
	}
}
func SetRecoverPanic(RecoverPanic bool) func(*ServerConfig) {
	return func(cfg *ServerConfig) {
		cfg.RecoverPanic = RecoverPanic
	}
}
func SetProfiler(Profiler bool) func(*ServerConfig) {
	return func(cfg *ServerConfig) {
		cfg.Profiler = Profiler
	}
}
func NewServerConfig(options ...func(*ServerConfig)) *ServerConfig {
	cfg := new(ServerConfig)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

func SetServerConfig(cfg *ServerConfig) func(*Server) {
	return func(s *Server) {
		s.Config = cfg
	}
}
func SetServerLogger(logger *golog.Logger) func(*Server) {
	return func(s *Server) {
		s.Logger = logger
	}
}

func NewServer(options ...func(*Server)) *Server {
	server := new(Server)
	server.Env = map[string]interface{}{}
	server.stopD = chanutil.NewDoneChan()
	for _, option := range options {
		option(server)
	}
	return server
}

func (s *Server) initServer() {
	if s.Config == nil {
		s.Config = &ServerConfig{}
	}

	if s.Logger == nil {
		s.Logger = golog.New("httpserver")
	}
}

type ContextHandler interface {
	ContextHandle(*Context) (interface{}, error)
}

type route struct {
	r              string
	cr             *regexp.Regexp
	method         string
	handler        reflect.Value
	httpHandler    http.Handler
	contextHandler ContextHandler
}

func (s *Server) addRoute(r string, method string, handler interface{}) {
	cr, err := regexp.Compile(r)
	if err != nil {
		s.Logger.Printf(golog.LEVEL_ERROR, "Error in route regex %s\nStack:\n%s", r, debug.Stack())
		return
	}

	switch handler.(type) {
	case http.Handler:
		s.routes = append(s.routes, route{r: r, cr: cr, method: method, httpHandler: handler.(http.Handler)})
	case ContextHandler:
		s.routes = append(s.routes, route{r: r, cr: cr, method: method, contextHandler: handler.(ContextHandler)})
	case reflect.Value:
		fv := handler.(reflect.Value)
		s.routes = append(s.routes, route{r: r, cr: cr, method: method, handler: fv})
	default:
		fv := reflect.ValueOf(handler)
		s.routes = append(s.routes, route{r: r, cr: cr, method: method, handler: fv})
	}
}

// ServeHTTP is the interface method for Go's http server package
func (s *Server) ServeHTTP(c http.ResponseWriter, req *http.Request) {
	s.Process(c, req)
}

// Process invokes the routing system for server s
func (s *Server) Process(c http.ResponseWriter, req *http.Request) {
	route := s.routeHandler(req, c)
	if route != nil {
		route.httpHandler.ServeHTTP(c, req)
	}
}

// Get adds a handler for the 'GET' http method for server s.
func (s *Server) Get(route string, handler interface{}) {
	s.addRoute(route, "GET", handler)
}

// Post adds a handler for the 'POST' http method for server s.
func (s *Server) Post(route string, handler interface{}) {
	s.addRoute(route, "POST", handler)
}

// Put adds a handler for the 'PUT' http method for server s.
func (s *Server) Put(route string, handler interface{}) {
	s.addRoute(route, "PUT", handler)
}

// Delete adds a handler for the 'DELETE' http method for server s.
func (s *Server) Delete(route string, handler interface{}) {
	s.addRoute(route, "DELETE", handler)
}

// Match adds a handler for an arbitrary http method for server s.
func (s *Server) Match(method string, route string, handler interface{}) {
	s.addRoute(route, method, handler)
}

//Adds a custom handler. Only for webserver mode. Will have no effect when running as FCGI or SCGI.
func (s *Server) Handler(route string, method string, httpHandler http.Handler) {
	s.addRoute(route, method, httpHandler)
}

//Adds a handler for websockets. Only for webserver mode. Will have no effect when running as FCGI or SCGI.
//func (s *Server) Websocket(route string, httpHandler websocket.Handler) {
//	s.addRoute(route, "GET", httpHandler)
//}

// Run starts the web application and serves HTTP requests for s
func (s *Server) Run(addr string) {
	s.initServer()

	mux := http.NewServeMux()
	if s.Config.Profiler {
		mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	}
	mux.Handle("/", s)

	s.Logger.Printf(golog.LEVEL_INFO, "http serving %s", addr)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	s.l = l

	srv := &http.Server{Handler: mux}
	srv.ErrorLog = log.New(s.Logger.Out, fmt.Sprintf("%s %s ", golog.LevelString[golog.LEVEL_ERROR], s.Logger.Name), s.Logger.Flag)
	err = srv.Serve(s.l)
	//	err = http.Serve(s.l, mux)
	if err != nil {
		panic(err)
	}
}

// RunFcgi starts the web application and serves FastCGI requests for s.
func (s *Server) RunFcgi(addr string) {
	s.initServer()
	s.Logger.Printf(golog.LEVEL_INFO, "http serving fcgi %s", addr)
	err := s.listenAndServeFcgi(addr)
	if err != nil {
		panic(err)
	}
}

// RunScgi starts the web application and serves SCGI requests for s.
func (s *Server) RunScgi(addr string) {
	s.initServer()
	s.Logger.Printf(golog.LEVEL_INFO, "http serving scgi %s", addr)
	err := s.listenAndServeScgi(addr)
	if err != nil {
		panic(err)
	}
}

// RunTLS starts the web application and serves HTTPS requests for s.
func (s *Server) RunTLS(addr string, config *tls.Config) {
	s.initServer()
	mux := http.NewServeMux()
	mux.Handle("/", s)
	l, err := tls.Listen("tcp", addr, config)
	if err != nil {
		panic(err)
	}
	s.l = l
	srv := &http.Server{Handler: mux}
	srv.ErrorLog = log.New(s.Logger.Out, fmt.Sprintf("%s %s ", golog.LevelString[golog.LEVEL_ERROR], s.Logger.Name), s.Logger.Flag)
	err = srv.Serve(s.l)
	//	err = http.Serve(s.l, mux)
	if err != nil {
		panic(err)
	}
}

func (s *Server) RunMux(wg *sync.WaitGroup, addr string) {
	s.initServer()
	err := s.startListen(1, addr)
	if err != nil {
		panic(err)
	}
	s.wg = wg
	wg.Add(1)
	go s.working(addr)
}

func (s *Server) working(addr string) {
	defer func() {
		if !s.Closed() {
			if e := recover(); e != nil {
				s.Logger.Errorf("recover http error:%s", e)
			}
			//尝试重连
			err := s.startListen(MAXN_RETRY_TIMES, addr)
			if err != nil { //重连失败
				s.Close()
			} else { //重连成功，继续工作
				go s.working(addr)
			}
		} else {
			if e := recover(); e != nil {
				s.Logger.Debugf("recover http error=%+v", e)
			}
		}
	}()
	mux := http.NewServeMux()
	if s.Config.Profiler {
		mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	}
	mux.Handle("/", s)
	srv := &http.Server{Handler: mux}
	srv.ErrorLog = log.New(s.Logger.Out, fmt.Sprintf("%s %s ", golog.LevelString[golog.LEVEL_ERROR], s.Logger.Name), s.Logger.Flag)
	err := srv.Serve(s.l)
	//	err = http.Serve(s.l, mux)
	if err != nil {
		panic(err)
	}
}

func (s *Server) startListen(trytime int, addr string) error {
	s.Logger.Printf(golog.LEVEL_INFO, "http serving %s", addr)
	trytime--
	err := func() error {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		s.l = l
		return nil
	}()
	if err != nil {
		if trytime > 0 {
			time.Sleep(1 * time.Second)
			s.Logger.Errorf("tcp: Listen error:%s; retrying %d", err, trytime+1)
			return s.startListen(trytime, addr)
		} else {
			return err
		}
	}
	return nil
}

// RunTLS starts the web application and serves HTTPS requests for s.
func (s *Server) RunTLSMux(wg *sync.WaitGroup, addr string, config *tls.Config) {
	s.initServer()
	err := s.startListenTLS(1, addr, config)
	if err != nil {
		panic(err)
	}
	s.wg = wg
	wg.Add(1)
	go s.workingTls(addr, config)
}

func (s *Server) workingTls(addr string, config *tls.Config) {
	defer func() {
		if !s.Closed() {
			if e := recover(); e != nil {
				s.Logger.Debugf("recover http error:%s", e)
			}
			//尝试重连
			err := s.startListenTLS(MAXN_RETRY_TIMES, addr, config)
			if err != nil { //重连失败
				s.Close()
			} else { //重连成功，继续工作
				go s.workingTls(addr, config)
			}
		} else {
			if e := recover(); e != nil {
				s.Logger.Debugf("recover http error:%s", e)
			}
		}
	}()
	mux := http.NewServeMux()
	mux.Handle("/", s)
	srv := &http.Server{Handler: mux}
	srv.ErrorLog = log.New(s.Logger.Out, fmt.Sprintf("%s %s ", golog.LevelString[golog.LEVEL_ERROR], s.Logger.Name), s.Logger.Flag)
	err := srv.Serve(s.l)
	//	err = http.Serve(s.l, mux)
	if err != nil {
		panic(err)
	}
}

func (s *Server) startListenTLS(trytime int, addr string, config *tls.Config) error {
	s.Logger.Printf(golog.LEVEL_INFO, "http serving %s", addr)
	trytime--
	err := func() error {
		l, err := tls.Listen("tcp", addr, config)
		if err != nil {
			return err
		}
		s.l = l
		return nil
	}()
	if err != nil {
		if trytime > 0 {
			time.Sleep(1 * time.Second)
			s.Logger.Errorf("tcp: Listen error:%s; retrying %v", err, trytime+1)
			return s.startListenTLS(trytime, addr, config)
		} else {
			return err
		}
	}
	return nil
}

// Close stops server s.
func (s *Server) Close() {
	s.stopOnce.Do(func() {
		defer func() { recover() }()
		s.stopD.SetDone()
		if s.wg != nil {
			s.wg.Done()
		}
		if s.l != nil {
			s.l.Close()
		}
	})
}

func (s *Server) Closed() bool {
	return s.stopD.R().Done()
}

// safelyCall invokes `function` in recover block
func (s *Server) safelyCall(function reflect.Value, args []reflect.Value) (resp []reflect.Value, err interface{}) {
	defer func() {
		if e := recover(); e != nil {
			if !s.Config.RecoverPanic {
				// go back to panic
				panic(e)
			} else {
				err = e
				resp = nil
				s.Logger.Printf(golog.LEVEL_WARN, "Handler crashed with content=%+v", err)
			}
		}
	}()
	resp = function.Call(args)
	return
}

func (s *Server) safelyCtxHandler(handler ContextHandler, ctx *Context) (resp []reflect.Value, err interface{}) {
	defer func() {
		if e := recover(); e != nil {
			if !s.Config.RecoverPanic {
				// go back to panic
				panic(e)
			} else {
				err = e
				resp = nil
				s.Logger.Printf(golog.LEVEL_WARN, "Handler crashed with content=%+v", err)
			}
		}
	}()
	var ret interface{}
	ret, err = handler.ContextHandle(ctx)
	if err != nil {
		return
	}
	resp = []reflect.Value{reflect.ValueOf(ret)}
	return
}

// requiresContext determines whether 'handlerType' contains
// an argument to 'web.Ctx' as its first argument
func requiresContext(handlerType reflect.Type) bool {
	//if the method doesn't take arguments, no
	if handlerType.NumIn() == 0 {
		return false
	}

	//if the first argument is not a pointer, no
	a0 := handlerType.In(0)
	if a0.Kind() != reflect.Ptr {
		return false
	}
	//if the first argument is a context, yes
	if a0.Elem() == contextType {
		return true
	}

	return false
}

// tryServingFile attempts to serve a static file, and returns
// whether or not the operation is successful.
// It checks the following directories for the file, in order:
// 1) Config.StaticDir
// 2) The 'static' directory in the parent directory of the executable.
// 3) The 'static' directory in the current working directory
func (s *Server) tryServingFile(name string, req *http.Request, w http.ResponseWriter) bool {
	//try to serve a static file
	if s.Config.StaticDir != "" {
		staticFile := path.Join(s.Config.StaticDir, name)
		if fileExists(staticFile) {
			http.ServeFile(w, req, staticFile)
			return true
		}
	} else {
		for _, staticDir := range defaultStaticDirs {
			staticFile := path.Join(staticDir, name)
			if fileExists(staticFile) {
				http.ServeFile(w, req, staticFile)
				return true
			}
		}
	}
	return false
}

func (s *Server) logRequest(ctx Context, sTime time.Time) {
	//log the request
	req := ctx.Request
	requestPath := req.URL.Path

	duration := time.Now().Sub(sTime)
	var client string
	// We suppose RemoteAddr is of the form Ip:Port as specified in the Request
	// documentation at http://golang.org/pkg/net/http/#Request
	pos := strings.LastIndex(req.RemoteAddr, ":")
	if pos > 0 {
		client = req.RemoteAddr[0:pos]
	} else {
		client = req.RemoteAddr
	}

	if len(ctx.Params) > 0 {
		ctx.Server.Logger.Println(golog.LEVEL_DEBUG, fmt.Sprintf("%s %s %s - %v -Params: %+v", client, req.Method, requestPath, duration, ctx.Params))
	} else {
		ctx.Server.Logger.Println(golog.LEVEL_DEBUG, fmt.Sprintf("%s %s %s - %v", client, req.Method, requestPath, duration))
	}

}

// the main route handler in web.go
// Tries to handle the given request.
// Finds the route matching the request, and execute the callback associated
// with it.  In case of custom http handlers, this function returns an "unused"
// route. The caller is then responsible for calling the httpHandler associated
// with the returned route.
func (s *Server) routeHandler(req *http.Request, w http.ResponseWriter) (unused *route) {
	requestPath := req.URL.Path
	ctx := Context{req, map[string]string{}, s, w}

	//set some default headers
	ctx.SetHeader("Server", HTTP_HEAD, true)
	tm := time.Now().UTC()

	//ignore errors from ParseForm because it's usually harmless.
	req.ParseForm()
	if len(req.Form) > 0 {
		for k, v := range req.Form {
			ctx.Params[k] = v[0]
		}
	}

	defer s.logRequest(ctx, tm)

	ctx.SetHeader("Date", webTime(tm), true)

	if req.Method == "GET" || req.Method == "HEAD" {
		if s.tryServingFile(requestPath, req, w) {
			return
		}
	}

	//Set the default content-type
	ctx.SetHeader("Content-Type", "text/html; charset=utf-8", true)

	for i := 0; i < len(s.routes); i++ {
		route := s.routes[i]
		cr := route.cr
		//if the methods don't match, skip this handler (except HEAD can be used in place of GET)
		if req.Method != route.method && !(req.Method == "HEAD" && route.method == "GET") {
			continue
		}

		if !cr.MatchString(requestPath) {
			continue
		}
		match := cr.FindStringSubmatch(requestPath)

		if len(match[0]) != len(requestPath) {
			continue
		}

		if route.httpHandler != nil {
			unused = &route
			// We can not handle custom http handlers here, give back to the caller.
			return
		}
		var ret []reflect.Value
		var err interface{}
		if route.contextHandler != nil {
			ret, err = s.safelyCtxHandler(route.contextHandler, &ctx)
		} else {
			var args []reflect.Value
			handlerType := route.handler.Type()
			if requiresContext(handlerType) {
				args = append(args, reflect.ValueOf(&ctx))
			}
			for _, arg := range match[1:] {
				args = append(args, reflect.ValueOf(arg))
			}
			ret, err = s.safelyCall(route.handler, args)
		}
		if err != nil {
			//there was an error or panic while calling the handler
			//			ctx.Abort(500, "Server Error")
			switch e := err.(type) {
			case string:
				ctx.Abort(500, e)
			case error:
				ctx.Abort(500, e.Error())
			default:
				bb, err1 := json.Marshal(err)
				if err1 == nil {
					ctx.SetHeader("Content-Type", "application/json", true)
					ctx.AbortBytes(500, bb)
				} else {
					ctx.Abort(500, fmt.Sprintf("%+v", err))
				}
			}
		}
		if len(ret) == 0 {
			return
		}
		sval := ret[0]
		var content []byte
		if sval.Kind() == reflect.String {
			content = []byte(sval.String())
		} else if sval.Kind() == reflect.Slice && sval.Type().Elem().Kind() == reflect.Uint8 {
			content = sval.Interface().([]byte)
		} else {
			bb, err1 := json.Marshal(sval.Interface())
			if err1 == nil {
				ctx.SetHeader("Content-Type", "application/json", true)
				content = bb
			}
		}
		if content != nil {
			ctx.SetHeader("Content-Length", strconv.Itoa(len(content)), true)
			ctx.WriteBytes(content)
		}
		return
	}

	// try serving index.html or index.htm
	if req.Method == "GET" || req.Method == "HEAD" {
		if s.tryServingFile(path.Join(requestPath, "index.html"), req, w) {
			return
		} else if s.tryServingFile(path.Join(requestPath, "index.htm"), req, w) {
			return
		}
	}
	ctx.Abort(404, "Page not found")
	return
}

// SetLogger sets the logger for server s
func (s *Server) SetLogger(logger *golog.Logger) {
	s.Logger = logger
}
