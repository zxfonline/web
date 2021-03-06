// Package web is a lightweight web framework for Go. It's ideal for
// writing simple, performant backend web services.

package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zxfonline/gerror"
	"github.com/zxfonline/golog"
	"github.com/zxfonline/iptable"

	trace "github.com/zxfonline/golangtrace"
)

// A Context object is created for every incoming HTTP request, and is
// passed to handlers as an optional first argument. It provides information
// about the request, including the http.Request object, the GET and POST params,
// and acts as a Writer for the response.

type Context struct {
	Request     *http.Request
	RequestBody []byte
	Params      map[string]string
	Server      *Server
	http.ResponseWriter
	tr trace.Trace
}

var (
	acceptsHtmlRegex = regexp.MustCompile(`(text/html|application/xhtml\+xml)(?:,|$)`)
	acceptsXmlRegex  = regexp.MustCompile(`(application/xml|text/xml)(?:,|$)`)
	acceptsJsonRegex = regexp.MustCompile(`(application/json)(?:,|$)`)
)

func (ctx *Context) TraceFinish() {
	if ctx.tr != nil {
		ctx.tr.Finish()
		ctx.tr = nil
	}
}
func (ctx *Context) TracePrintf(format string, a ...interface{}) {
	if ctx.tr != nil {
		ctx.tr.LazyPrintf(format, a...)
	}
}

func (ctx *Context) TraceErrorf(format string, a ...interface{}) {
	if ctx.tr != nil {
		ctx.tr.LazyPrintf(format, a...)
		ctx.tr.SetError()
	}
}

// Protocol returns request protocol name, such as HTTP/1.1 .
func (ctx *Context) Protocol() string {
	return ctx.Request.Proto
}

// Uri returns full request url with query string, fragment.
func (ctx *Context) Uri() string {
	return ctx.Request.RequestURI
}

// Url returns request url path (without query string, fragment).
func (ctx *Context) Url() string {
	return ctx.Request.URL.Path
}

// Site returns base site url as scheme://domain type.
func (ctx *Context) Site() string {
	return ctx.Scheme() + "://" + ctx.Domain()
}

// Scheme returns request scheme as "http" or "https".
func (ctx *Context) Scheme() string {
	if ctx.Request.URL.Scheme != "" {
		return ctx.Request.URL.Scheme
	}
	if ctx.Request.TLS == nil {
		return "http"
	}
	return "https"
}

// Domain returns host name.
// Alias of Host method.
func (ctx *Context) Domain() string {
	return ctx.Host()
}

// Host returns host name.
// if no host info in request, return localhost.
func (ctx *Context) Host() string {
	if ctx.Request.Host != "" {
		hostParts := strings.Split(ctx.Request.Host, ":")
		if len(hostParts) > 0 {
			return hostParts[0]
		}
		return ctx.Request.Host
	}
	return "localhost"
}

// Method returns http request method.
func (ctx *Context) Method() string {
	return ctx.Request.Method
}

// Is returns boolean of this request is on given method, such as Is("POST").
func (ctx *Context) Is(method string) bool {
	return ctx.Method() == method
}

// Is this a GET method request?
func (ctx *Context) IsGet() bool {
	return ctx.Is("GET")
}

// Is this a POST method request?
func (ctx *Context) IsPost() bool {
	return ctx.Is("POST")
}

// Is this a Head method request?
func (ctx *Context) IsHead() bool {
	return ctx.Is("HEAD")
}

// Is this a OPTIONS method request?
func (ctx *Context) IsOptions() bool {
	return ctx.Is("OPTIONS")
}

// Is this a PUT method request?
func (ctx *Context) IsPut() bool {
	return ctx.Is("PUT")
}

// Is this a DELETE method request?
func (ctx *Context) IsDelete() bool {
	return ctx.Is("DELETE")
}

// Is this a PATCH method request?
func (ctx *Context) IsPatch() bool {
	return ctx.Is("PATCH")
}

// IsAjax returns boolean of this request is generated by ajax.
func (ctx *Context) IsAjax() bool {
	return ctx.Header("X-Requested-With") == "XMLHttpRequest"
}

// IsSecure returns boolean of this request is in https.
func (ctx *Context) IsSecure() bool {
	return ctx.Scheme() == "https"
}

// IsWebsocket returns boolean of this request is in webSocket.
func (ctx *Context) IsWebsocket() bool {
	return ctx.Header("Upgrade") == "websocket"
}

// IsUpload returns boolean of whether file uploads in this request or not..
func (ctx *Context) IsUpload() bool {
	return strings.Contains(ctx.Header("Content-Type"), "multipart/form-data")
}

// Checks if request accepts html response
func (ctx *Context) AcceptsHtml() bool {
	return acceptsHtmlRegex.MatchString(ctx.Header("Accept"))
}

// Checks if request accepts xml response
func (ctx *Context) AcceptsXml() bool {
	return acceptsXmlRegex.MatchString(ctx.Header("Accept"))
}

// Checks if request accepts json response
func (ctx *Context) AcceptsJson() bool {
	return acceptsJsonRegex.MatchString(ctx.Header("Accept"))
}

// IP returns request client ip.
// if in proxy, return first proxy id.
// if error, return 127.0.0.1.
func (ctx *Context) IP() string {
	ips := ctx.Proxy()
	if len(ips) > 0 && ips[0] != "" {
		rip := strings.Split(ips[0], ":")
		return rip[0]
	}
	ip := strings.Split(ctx.Request.RemoteAddr, ":")
	if len(ip) > 0 {
		if ip[0] != "[" {
			return ip[0]
		}
	}
	return "127.0.0.1"
}

// Proxy returns proxy client ips slice.
func (ctx *Context) Proxy() []string {
	if ips := ctx.Header("X-Forwarded-For"); ips != "" {
		return strings.Split(ips, ",")
	}
	return []string{}
}

// Referer returns http referer header.
func (ctx *Context) Referer() string {
	return ctx.Header("Referer")
}

// Refer returns http referer header.
func (ctx *Context) Refer() string {
	return ctx.Referer()
}

// SubDomains returns sub domain string.
// if aa.bb.domain.com, returns aa.bb .
func (ctx *Context) SubDomains() string {
	parts := strings.Split(ctx.Host(), ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-2], ".")
	}
	return ""
}

// Port returns request client port.
// when error or empty, return 80.
func (ctx *Context) Port() int {
	parts := strings.Split(ctx.Request.Host, ":")
	if len(parts) == 2 {
		port, _ := strconv.Atoi(parts[1])
		return port
	}
	return 80
}

// UserAgent returns request client user agent string.
func (ctx *Context) UserAgent() string {
	return ctx.Header("User-Agent")
}

// Header returns request header item string by a given string.
// if non-existed, return empty string.
func (ctx *Context) Header(key string) string {
	return ctx.Request.Header.Get(key)
}

// Cookie returns request cookie item string by a given key.
// if non-existed, return empty string.
func (ctx *Context) Cookie(key string) string {
	ck, err := ctx.Request.Cookie(key)
	if err != nil {
		return ""
	}
	return ck.Value
}

// CopyBody returns the raw request body data as bytes.
func (ctx *Context) CopyBody() []byte {
	requestbody, _ := ioutil.ReadAll(ctx.Request.Body)
	ctx.Request.Body.Close()
	bf := bytes.NewBuffer(requestbody)
	ctx.Request.Body = ioutil.NopCloser(bf)
	ctx.RequestBody = requestbody
	return requestbody
}

// parseForm or parseMultiForm based on Content-type
func (ctx *Context) ParseFormOrMulitForm(maxMemory int64) error {
	// Parse the body depending on the content type.
	if ctx.IsUpload() {
		if err := ctx.Request.ParseMultipartForm(maxMemory); err != nil {
			return errors.New("Error parsing request body:" + err.Error())
		}
	} else if err := ctx.Request.ParseForm(); err != nil {
		return errors.New("Error parsing request body:" + err.Error())
	}
	return nil
}

// WriteString writes string data into the response object.
func (ctx *Context) WriteString(content string) {
	ctx.ResponseWriter.Write([]byte(content))
}

// WriteString writes string data into the response object.
func (ctx *Context) WriteBytes(content []byte) {
	ctx.ResponseWriter.Write(content)
}

// Abort is a helper method that sends an HTTP header and an optional
// body. It is useful for returning 4xx or 5xx errors.
// Once it has been called, any return value from the handler will
// not be written to the response.
func (ctx *Context) Abort(status int, body string) {
	ctx.ResponseWriter.WriteHeader(status)
	ctx.ResponseWriter.Write([]byte(body))
}

// Abort is a helper method that sends an HTTP header and an optional
// body. It is useful for returning 4xx or 5xx errors.
// Once it has been called, any return value from the handler will
// not be written to the response.
func (ctx *Context) AbortBytes(status int, body []byte) {
	ctx.ResponseWriter.WriteHeader(status)
	ctx.ResponseWriter.Write(body)
}

// Redirect is a helper method for 3xx redirects.
func (ctx *Context) Redirect(status int, url_ string) {
	ctx.ResponseWriter.Header().Set("Location", url_)
	ctx.ResponseWriter.WriteHeader(status)
	ctx.ResponseWriter.Write([]byte("Redirecting to: " + url_))
}

// Notmodified writes a 304 HTTP response
func (ctx *Context) NotModified() {
	ctx.ResponseWriter.WriteHeader(304)
}

// NotFound writes a 404 HTTP response
func (ctx *Context) NotFound(message string) {
	ctx.ResponseWriter.WriteHeader(404)
	ctx.ResponseWriter.Write([]byte(message))
}

//Unauthorized writes a 401 HTTP response
func (ctx *Context) Unauthorized() {
	ctx.ResponseWriter.WriteHeader(401)
}

//Forbidden writes a 403 HTTP response
func (ctx *Context) Forbidden() {
	ctx.ResponseWriter.WriteHeader(403)
}

// ContentType sets the Content-Type header for an HTTP response.
// For example, ctx.ContentType("json") sets the content-type to "application/json"
// If the supplied value contains a slash (/) it is set as the Content-Type
// verbatim. The return value is the content type as it was
// set, or an empty string if none was found.
func (ctx *Context) ContentType(val string) string {
	var ctype string
	if strings.ContainsRune(val, '/') {
		ctype = val
	} else {
		if !strings.HasPrefix(val, ".") {
			val = "." + val
		}
		ctype = mime.TypeByExtension(val)
	}
	if ctype != "" {
		ctx.SetHeader("Content-Type", ctype, true)
	}
	return ctype
}

// SetHeader sets a response header. If `unique` is true, the current value
// of that header will be overwritten . If false, it will be appended.
func (ctx *Context) SetHeader(hdr string, val string, unique bool) {
	if unique {
		ctx.ResponseWriter.Header().Set(hdr, val)
	} else {
		ctx.ResponseWriter.Header().Add(hdr, val)
	}
}

// SetCookie adds a cookie header to the response.
func (ctx *Context) SetCookie(cookie *http.Cookie) {
	ctx.SetHeader("Set-Cookie", cookie.String(), false)
}

func (ctx *Context) SetExpires(expires time.Duration) {
	ctx.SetHeader("Expires", webTime(time.Now().Add(expires)), true)
}

func (ctx *Context) SetCacheControl(expires time.Duration) {
	if expires > time.Second {
		ctx.SetHeader("Expires", webTime(time.Now().Add(expires)), true)
		ctx.SetHeader("Cache-Control", fmt.Sprintf("max-age=%d", int(expires.Seconds())), true)
	} else {
		ctx.SetHeader("Expires", webTime(time.Now()), true)
		ctx.SetHeader("Cache-Control", "no-cache", true)
	}
}

func (ctx *Context) SetLastModified(modtime time.Time) {
	ctx.SetHeader("Last-Modified", webTime(modtime), true)
}

func getCookieSig(key string, val []byte, timestamp string) string {
	hm := hmac.New(sha1.New, []byte(key))

	hm.Write(val)
	hm.Write([]byte(timestamp))

	hex := fmt.Sprintf("%02x", hm.Sum(nil))
	return hex
}

func (ctx *Context) SetSecureCookie(name string, val string, age int64) {
	//base64 encode the val
	if len(ctx.Server.Config.CookieSecret) == 0 {
		ctx.Server.Logger.Println(golog.LEVEL_WARN, "Secret Key for secure cookies has not been set. Please assign a cookie secret to web.Config.CookieSecret.")
		return
	}
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write([]byte(val))
	encoder.Close()
	vs := buf.String()
	vb := buf.Bytes()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := getCookieSig(ctx.Server.Config.CookieSecret, vb, timestamp)
	cookie := strings.Join([]string{vs, timestamp, sig}, "|")
	ctx.SetCookie(NewCookie(name, cookie, age))
}

func (ctx *Context) GetSecureCookie(name string) (string, bool) {
	for _, cookie := range ctx.Request.Cookies() {
		if cookie.Name != name {
			continue
		}

		parts := strings.SplitN(cookie.Value, "|", 3)

		val := parts[0]
		timestamp := parts[1]
		sig := parts[2]

		if getCookieSig(ctx.Server.Config.CookieSecret, []byte(val), timestamp) != sig {
			return "", false
		}

		ts, _ := strconv.ParseInt(timestamp, 0, 64)

		if time.Now().Unix()-31*86400 > ts {
			return "", false
		}

		buf := bytes.NewBufferString(val)
		encoder := base64.NewDecoder(base64.StdEncoding, buf)

		res, _ := ioutil.ReadAll(encoder)
		return string(res), true
	}
	return "", false
}

// small optimization: cache the context type instead of repeteadly calling reflect.Typeof
var contextType reflect.Type

var defaultStaticDirs []string

func init() {
	contextType = reflect.TypeOf(Context{})
	//find the location of the exe file
	wd, _ := os.Getwd()
	exeFile := path.Clean(os.Args[0])
	parent, _ := filepath.Split(exeFile)
	//1：命令执行所在目录
	wdDir := strings.Replace(filepath.Clean(filepath.Join(wd, "static")), "\\", "/", -1)
	defaultStaticDirs = append(defaultStaticDirs, wdDir)
	exeDir := strings.Replace(filepath.Clean(filepath.Join(parent, "static")), "\\", "/", -1)
	if wdDir != exeDir { //2：可执行文件所在目录
		defaultStaticDirs = append(defaultStaticDirs, exeDir)
	}
	exeLastDir := strings.Replace(filepath.Clean(filepath.Join(parent, "..", "static")), "\\", "/", -1)
	if wdDir != exeLastDir { //3：可执行文件上一级目录
		defaultStaticDirs = append(defaultStaticDirs, exeLastDir)
	}
}

// Process invokes the main server's routing system.
func Process(c http.ResponseWriter, req *http.Request) {
	mainServer.Process(c, req)
}

// Run starts the web application and serves HTTP requests for the main server.
func Run(addr string) (err error) {
	defer gerror.PanicToErr(&err)
	mainServer.Run(addr)
	return
}

// RunTLS starts the web application and serves HTTPS requests for the main server.
func RunTLS(addr string, config *tls.Config) (err error) {
	defer gerror.PanicToErr(&err)
	mainServer.RunTLS(addr, config)
	return
}

// RunScgi starts the web application and serves SCGI requests for the main server.
func RunScgi(addr string) (err error) {
	defer gerror.PanicToErr(&err)
	mainServer.RunScgi(addr)
	return
}

// RunFcgi starts the web application and serves FastCGI requests for the main server.
func RunFcgi(addr string) (err error) {
	defer gerror.PanicToErr(&err)
	mainServer.RunFcgi(addr)
	return
}

// Close stops the main server.
func Close() {
	mainServer.Close()
}

// Get adds a handler for the 'GET' http method in the main server.
func Get(route string, handler interface{}) {
	mainServer.Get(route, handler)
}

// Post adds a handler for the 'POST' http method in the main server.
func Post(route string, handler interface{}) {
	mainServer.Post(route, handler)
}

// Put adds a handler for the 'PUT' http method in the main server.
func Put(route string, handler interface{}) {
	mainServer.Put(route, handler)
}

// Delete adds a handler for the 'DELETE' http method in the main server.
func Delete(route string, handler interface{}) {
	mainServer.Delete(route, handler)
}

// Match adds a handler for an arbitrary http method in the main server.
func Match(route string, handler interface{}, method string) {
	mainServer.Match(route, handler, method)
}

// SetLogger sets the logger for the main server.
func SetLogger(logger *golog.Logger) {
	mainServer.Logger = logger
}

var Config = NewServerConfig()
var Logger = golog.New("HttpServer")
var mainServer = NewServer(SetServerConfig(Config), SetServerLogger(Logger))

//检查指定服务是否可用
func CheckServiceEnable(ctx *Context) bool {
	ipStr := iptable.RequestIP(ctx.Request)
	return !iptable.IsBlackIp(ipStr)
}

//是否是受信任的地址
func IsTrustedIP(ctx *Context) bool {
	ipStr := iptable.RequestIP(ctx.Request)
	return iptable.IsTrustedIP(ipStr)
}
