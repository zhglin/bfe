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

package bfe_conf

import (
	gcfg "gopkg.in/gcfg.v1"
)

type BfeConfig struct {
	// basic server config 基本的服务器配置
	Server ConfigBasic

	// basic https config https的基本配置
	HttpsBasic ConfigHttpsBasic

	// session cache config
	SessionCache ConfigSessionCache

	// session cache config
	SessionTicket ConfigSessionTicket
}

// SetDefaultConf 设置默认配置
func SetDefaultConf(conf *BfeConfig) {
	conf.Server.SetDefaultConf()
	conf.HttpsBasic.SetDefaultConf()
	conf.SessionCache.SetDefaultConf()
	conf.SessionTicket.SetDefaultConf()
}

// BfeConfigLoad loads config from config file.
// NOTICE: some value will be modified when not set or out of range!!
// BfeConfigLoad从配置文件中加载配置。
// 注意:某些值在未设置或超出范围时将被修改!!
func BfeConfigLoad(filePath string, confRoot string) (BfeConfig, error) {
	var cfg BfeConfig
	var err error

	// 设置默认的配置项
	SetDefaultConf(&cfg)

	// read config from file 从文件中读取配置
	err = gcfg.ReadFileInto(&cfg, filePath)
	if err != nil {
		return cfg, err
	}

	// 校验server配置
	if err = cfg.Server.Check(confRoot); err != nil {
		return cfg, err
	}

	// 校验httpsServer配置
	if err = cfg.HttpsBasic.Check(confRoot); err != nil {
		return cfg, err
	}

	if err = cfg.SessionCache.Check(confRoot); err != nil {
		return cfg, err
	}

	if err = cfg.SessionTicket.Check(confRoot); err != nil {
		return cfg, err
	}

	return cfg, nil
}
