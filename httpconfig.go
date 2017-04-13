// Copyright 2016 zxfonline@sina.com. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package web

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/knadh/jsonconfig"
	"github.com/zxfonline/fileutil"
	"github.com/zxfonline/golog"
	"github.com/zxfonline/iptable"
)

//默认全局http过滤器
var ServiceConfig *HttpServiceConfig = &HttpServiceConfig{Routers: make(map[string]Router)}

//加载全局http服务过滤配置文件
func LoadHttpServiceConfig() *HttpServiceConfig {
	configurl := os.Getenv("httpCfg")
	if configurl == "" {
		panic(errors.New(`没找到系统变量:"httpCfg"`))
	}
	configurl = fileutil.TransPath(configurl)
	httpconfig := new(HttpServiceConfig)
	if err := jsonconfig.Load(configurl, httpconfig); err != nil {
		panic(fmt.Errorf("加载HTTP SERVICE 过滤文件[%s]错误,error=%v", configurl, err))
	}
	golog.Infof("LOAD HTTP SERVICE FILTER:\n%+v", *httpconfig)
	//替换全局过滤器
	ServiceConfig = httpconfig
	return httpconfig
}

type HttpServiceConfig struct {
	Profiler     bool              `json:"profiler"`
	WriteTimeout uint              `json:"writeTimeout"`
	ReadTimeout  uint              `json:"readTimeout"`
	KeepAlive    bool              `json:"keepalive"`
	Routers      map[string]Router `json:"routers"`
}

type Router struct {
	Methods []string `json:"methods"`
	//是否对没有ip权限的访问开启
	Enable bool `json:"enable"`
}

//消息处理派发器
type HttpService struct {
	cache  map[string]*Service
	logger *golog.Logger
}

//检查指定服务是否可用
func CheckServiceEnable(ctx *Context) bool {
	url := ctx.Request.URL.Path
	method := ctx.Request.Method
	ipStr := iptable.GetRemoteAddrIP(ctx.Request.RemoteAddr)
	if r, ok := ServiceConfig.Routers[url]; ok { //没配置则默认通过
		if !r.Enable { //禁用
			// 过滤ip权限
			if !iptable.IsTrustedIP(ipStr) {
				return false
			}
		}
		support := false
		for _, m := range r.Methods {
			if m == method {
				support = true
			}
		}
		if !support { //服务方法类型method不支持
			return false
		}
	}
	return !iptable.IsBlackIp(ipStr)
}

//服务代理
func (p *HttpService) ServiceHandle(ctx *Context, suburl string) (robj interface{}, err error) {
	if s, ok := p.cache[ctx.Request.URL.Path]; ok {
		if !CheckServiceEnable(ctx) {
			ctx.NotFound(http.StatusText(http.StatusNotFound))
			return
		}
		robj, err = s.ServiceCall(ctx)
		return
	}
	ctx.NotFound(http.StatusText(http.StatusNotFound))
	return
}

func (p *HttpService) RegistHandler(route string, service *Service) error {
	if route == "" || service == nil {
		return errors.New("illegal regist handler error")
	}
	if _, ok := p.cache[route]; ok {
		return fmt.Errorf("repeat regist service handler error, handler=%+v", route)
	}
	p.cache[route] = service
	p.logger.Infof("Regist http service handler=%s", route)
	return nil
}

//创建消息处理派发器
func NewHttpService(logger *golog.Logger) *HttpService {
	return &HttpService{
		cache:  make(map[string]*Service),
		logger: logger,
	}
}
