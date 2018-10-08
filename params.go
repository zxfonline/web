// Copyright 2016 zxfonline@sina.com. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package web

import (
	"fmt"

	. "github.com/zxfonline/strutil"
)

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamU64(key string, def ...uint64) uint64 {
	if v, ok := ctx.Params[key]; ok {
		return Stou64(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamU32(key string, def ...uint32) uint32 {
	if v, ok := ctx.Params[key]; ok {
		return Stou32(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamU16(key string, def ...uint16) uint16 {
	if v, ok := ctx.Params[key]; ok {
		return Stou16(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamU8(key string, def ...uint8) uint8 {
	if v, ok := ctx.Params[key]; ok {
		return Stou8(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamU(key string, def ...uint) uint {
	if v, ok := ctx.Params[key]; ok {
		return Stou(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamI64(key string, def ...int64) int64 {
	if v, ok := ctx.Params[key]; ok {
		return Stoi64(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamI32(key string, def ...int32) int32 {
	if v, ok := ctx.Params[key]; ok {
		return Stoi32(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamI16(key string, def ...int16) int16 {
	if v, ok := ctx.Params[key]; ok {
		return Stoi16(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamI8(key string, def ...int8) int8 {
	if v, ok := ctx.Params[key]; ok {
		return Stoi8(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamI(key string, def ...int) int {
	if v, ok := ctx.Params[key]; ok {
		return Stoi(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamBol(key string, def ...bool) bool {
	if v, ok := ctx.Params[key]; ok {
		return StoBol(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamF32(key string, def ...float32) float32 {
	if v, ok := ctx.Params[key]; ok {
		return Stof32(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamF64(key string, def ...float64) float64 {
	if v, ok := ctx.Params[key]; ok {
		return Stof64(v, def...)
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

//没找到并且没有默认值则 panic抛错
func (ctx *Context) ParamStr(key string, def ...string) string {
	if v, ok := ctx.Params[key]; ok {
		return v
	} else if len(def) > 0 {
		return def[0]
	}
	panic(fmt.Errorf("no found param:%v", key))
}

// Param returns router param by a given key.没找到并且没有默认值则返回""字符串
func (ctx *Context) Param(key string, def ...string) string {
	if v, ok := ctx.Params[key]; ok {
		return v
	}
	var defv string
	if len(def) > 0 {
		defv = def[0]
	}
	return defv
}
