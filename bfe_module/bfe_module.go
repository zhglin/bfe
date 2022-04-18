// Copyright (c) 2019 The BFE Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// module framework for bfe

package bfe_module

import (
	"fmt"
	"path"
)

import (
	"github.com/baidu/go-lib/log"
	"github.com/baidu/go-lib/web-monitor/web_monitor"
)

import (
	"github.com/bfenetworks/bfe/bfe_util/json"
)

// BfeModule module统一接口
type BfeModule interface {
	// Name return name of module.
	// 返回模块名。
	Name() string

	// Init initializes the module.
	//
	// Params:
	//      - cbs: callback handlers. for register call back function
	//      - whs: web monitor handlers. for register web monitor handler
	//      - cr: config root path. for get config path of module
	// 初始化模块。
	// 参数:
	// - cbs:回调处理器。为寄存器回调函数
	// - whs: web监视器处理程序。注册web监视器处理程序
	// —cr:配置根路径。获取模块的配置路径
	Init(cbs *BfeCallbacks, whs *web_monitor.WebHandlers, cr string) error
}

// moduleMap holds mappings from mod_name to module.
// 保存从mod_name到模块的映射。
var moduleMap = make(map[string]BfeModule)

// modulesAll is an ordered list of all module names.
// modulesAll是所有模块名的有序列表。
var modulesAll = make([]string, 0)

// modulesEnabled is list of enabled module names.
// server启用的模块名列表。
var modulesEnabled = make([]string, 0)

// AddModule adds module to moduleMap and modulesAll.
// 将module添加到moduleMap和modulesAll。
func AddModule(module BfeModule) {
	moduleMap[module.Name()] = module
	modulesAll = append(modulesAll, module.Name())
}

// BfeModules 配置中开启的模块
type BfeModules struct {
	workModules map[string]BfeModule // work modules, configure in bfe conf file
}

// NewBfeModules create new BfeModules
// 创建BfeModules
func NewBfeModules() *BfeModules {
	bfeModules := new(BfeModules)
	bfeModules.workModules = make(map[string]BfeModule)

	return bfeModules
}

// RegisterModule register work module, only work module be inited
// 注册工作模块，只初始化工作模块
func (bm *BfeModules) RegisterModule(name string) error {
	module, ok := moduleMap[name]
	if !ok {
		return fmt.Errorf("no module for %s", name)
	}

	bm.workModules[name] = module

	return nil
}

// GetModule get work module by name.
func (bm *BfeModules) GetModule(name string) BfeModule {
	return bm.workModules[name]
}

// Init initializes bfe modules.
//
// Params:
//     - cbs: BfeCallbacks
//     - whs: WebHandlers
//     - cr : root path for config
// Init初始化bfe模块。
// 参数:
// - cbs: BfeCallbacks
// - whs: WebHandlers
// - cr: 配置文件的根路径
func (bm *BfeModules) Init(cbs *BfeCallbacks, whs *web_monitor.WebHandlers, cr string) error {
	// go through ALL available module names
	// It is IMPORTANT to do init by the order defined in modulesAll
	// 遍历所有可用的模块名
	// 按照modulesAll中定义的顺序执行init是很重要的
	for _, name := range modulesAll {
		// check whether this module is enabled
		// 检查该模块是否被启用
		module, ok := bm.workModules[name]
		if ok {
			// do init for this module
			// 对这个模块进行init
			err := module.Init(cbs, whs, cr)
			if err != nil {
				log.Logger.Error("Err in module.init() for %s [%s]",
					module.Name(), err.Error())
				return err
			}
			log.Logger.Info("%s:Init() OK", module.Name())

			// add to modulesEnabled
			modulesEnabled = append(modulesEnabled, name)
		}
	}
	return nil
}

// ModConfPath get full path of module config file.
//
// format: confRoot/<modName>/<modName>.conf
//
// e.g., confRoot = "/home/bfe/conf", modName = "mod_access"
// return "/home/bfe/conf/mod_access/mod_access.conf"
// ModConfPath获取模块配置文件的完整路径。
// 格式:confRoot/<modName>/<modName>.conf
// 例如，confRoot="/home/bfe/conf"， modName ="mod_access"
// 返回"/home/bfe/conf/mod_access/mod_access.conf”
func ModConfPath(confRoot string, modName string) string {
	confPath := path.Join(confRoot, modName, modName+".conf")
	return confPath
}

// ModConfDir get dir for module config.
//
// format: confRoot/<modName>
//
// e.g., confRoot = "/home/bfe/conf", modName = "mod_access"
// return "/home/bfe/conf/mod_access"
func ModConfDir(confRoot string, modName string) string {
	confDir := path.Join(confRoot, modName)
	return confDir
}

// ModuleStatusGetJSON get modules Available and modules Enabled.
func ModuleStatusGetJSON() ([]byte, error) {
	status := make(map[string][]string)
	status["available"] = modulesAll
	status["enabled"] = modulesEnabled
	return json.Marshal(status)
}
