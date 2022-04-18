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
	"fmt"
	"strings"
)

import (
	"github.com/baidu/go-lib/log"
)

import (
	"github.com/bfenetworks/bfe/bfe_util"
)

const (
	// BalancerProxy layer4均衡器工作在PROXY模式下
	BalancerProxy = "PROXY" // layer4 balancer working in PROXY mode (eg. F5, Ctrix, ELB etc)
	// BalancerNone layer4均衡器未使用
	BalancerNone = "NONE" // layer4 balancer not used
)

const (
	// LibrarySuffix defines BFE plugin's file suffix.
	LibrarySuffix = ".so"
)

// ConfigBasic 基本的服务器配置
type ConfigBasic struct {
	// HTTP监听端口
	HttpPort int // listen port for http
	// HTTPS监听端口
	HttpsPort int // listen port for https
	// 监控监控端口
	MonitorPort int // web server port for monitor
	// 使用的最大cpu数量
	MaxCpus int // number of max cpus to use
	// 每个监听器的accept goroutine数量，默认为1
	AcceptNum int // number of accept goroutine for each listener, default 1
	// 监视器的Web服务器是否启用
	MonitorEnabled bool // web server for monitor enable or not

	// settings of layer-4 load balancer
	Layer4LoadBalancer string

	// settings of communicate with http client

	// TLS握手超时，单位为秒
	TlsHandshakeTimeout int // tls handshake timeout, in seconds
	// 读取超时，以秒为单位
	ClientReadTimeout int // read timeout, in seconds
	// 写入超时，以秒为单位
	ClientWriteTimeout int // read timeout, in seconds
	// 优雅关机超时，以秒为单位
	GracefulShutdownTimeout int // graceful shutdown timeout, in seconds
	// 请求中以字节为单位的最大报头长度
	MaxHeaderBytes int // max header length in bytes in request
	// 请求中的最大URI(头)长度(以字节为单位)
	MaxHeaderUriBytes int // max URI(in header) length in bytes in request
	// 代理协议中的最大报头长度(字节)
	MaxProxyHeaderBytes int // max header length in bytes in Proxy protocol
	// 如果为false，则关闭客户端连接，忽略HTTP报头
	KeepAliveEnabled bool // if false, client connection is shutdown disregard of http headers

	Modules []string // modules to load
	// 插件
	Plugins []string // plugins to load

	// location of data files for bfe_route

	// host_rule.data路径
	HostRuleConf string // path of host_rule.data
	// vip_rule.data路径
	VipRuleConf string // path of vip_rule.data
	// route_rule.data路径
	RouteRuleConf string // path of route_rule.data

	// location of other data files
	// cluster_table.data路径
	ClusterTableConf string // path of cluster_table.data
	GslbConf         string // path of gslb.data
	// cluster_conf.data路径
	ClusterConf string // path of cluster_conf.data
	NameConf    string // path of name_conf.data

	// interval
	MonitorInterval int // interval for getting diff of proxy-state

	DebugServHttp    bool // whether open server http debug log
	DebugBfeRoute    bool // whether open bferoute debug log
	DebugBal         bool // whether open bal debug log
	DebugHealthCheck bool // whether open health check debug log
}

func (cfg *ConfigBasic) SetDefaultConf() {
	cfg.HttpPort = 8080
	cfg.HttpsPort = 8443
	cfg.MonitorPort = 8421
	cfg.MonitorEnabled = true
	cfg.MaxCpus = 0

	cfg.TlsHandshakeTimeout = 30
	cfg.ClientReadTimeout = 60
	cfg.ClientWriteTimeout = 60
	cfg.GracefulShutdownTimeout = 10
	cfg.MaxHeaderBytes = 1048576
	cfg.MaxHeaderUriBytes = 8192
	cfg.KeepAliveEnabled = true

	cfg.HostRuleConf = "server_data_conf/host_rule.data"
	cfg.VipRuleConf = "server_data_conf/vip_rule.data"
	cfg.RouteRuleConf = "server_data_conf/route_rule.data"

	cfg.ClusterTableConf = "cluster_conf/cluster_table.data"
	cfg.GslbConf = "cluster_conf/gslb.data"
	cfg.ClusterConf = "server_data_conf/cluster_conf.data"
	cfg.NameConf = "server_data_conf/name_conf.data"

	cfg.MonitorInterval = 20
}

// Check 校验配置
func (cfg *ConfigBasic) Check(confRoot string) error {
	return ConfBasicCheck(cfg, confRoot)
}

func ConfBasicCheck(cfg *ConfigBasic, confRoot string) error {
	var err error

	// check basic conf 检查基本配置
	err = basicConfCheck(cfg)
	if err != nil {
		return err
	}

	// check data file conf
	err = dataFileConfCheck(cfg, confRoot)
	if err != nil {
		return err
	}

	return nil
}

// 配置校验
func basicConfCheck(cfg *ConfigBasic) error {
	// check HttpPort
	if cfg.HttpPort < 1 || cfg.HttpPort > 65535 {
		return fmt.Errorf("HttpPort[%d] should be in [1, 65535]",
			cfg.HttpPort)
	}

	// check HttpsPort
	if cfg.HttpsPort < 1 || cfg.HttpsPort > 65535 {
		return fmt.Errorf("HttpsPort[%d] should be in [1, 65535]",
			cfg.HttpsPort)
	}

	// check MonitorPort if MonitorEnabled enabled
	if cfg.MonitorEnabled && (cfg.MonitorPort < 1 || cfg.MonitorPort > 65535) {
		return fmt.Errorf("MonitorPort[%d] should be in [1, 65535]",
			cfg.MonitorPort)
	}

	// check MaxCpus
	if cfg.MaxCpus < 0 {
		return fmt.Errorf("MaxCpus[%d] is too small", cfg.MaxCpus)
	}

	// check Layer4LoadBalancer
	if err := checkLayer4LoadBalancer(cfg); err != nil {
		return err
	}

	// check AcceptNum
	if cfg.AcceptNum < 0 {
		return fmt.Errorf("AcceptNum[%d] is too small", cfg.AcceptNum)
	} else if cfg.AcceptNum == 0 {
		cfg.AcceptNum = 1
	}

	// check TlsHandshakeTimeout
	if cfg.TlsHandshakeTimeout <= 0 {
		return fmt.Errorf("TlsHandshakeTimeout[%d] should > 0", cfg.TlsHandshakeTimeout)
	}
	if cfg.TlsHandshakeTimeout > 1200 {
		return fmt.Errorf("TlsHandshakeTimeout[%d] should <= 1200", cfg.TlsHandshakeTimeout)
	}

	// check ClientReadTimeout
	if cfg.ClientReadTimeout <= 0 {
		return fmt.Errorf("ClientReadTimeout[%d] should > 0", cfg.ClientReadTimeout)
	}

	// check ClientWriteTimeout
	if cfg.ClientWriteTimeout <= 0 {
		return fmt.Errorf("ClientWriteTimeout[%d] should > 0", cfg.ClientWriteTimeout)
	}

	// check GracefulShutdownTimeout
	if cfg.GracefulShutdownTimeout <= 0 || cfg.GracefulShutdownTimeout > 300 {
		return fmt.Errorf("GracefulShutdownTimeout[%d] should be (0, 300]", cfg.GracefulShutdownTimeout)
	}

	// check MonitorInterval
	if cfg.MonitorInterval <= 0 {
		// not set, use default value
		log.Logger.Warn("MonitorInterval not set, use default value(20)")
		cfg.MonitorInterval = 20
	} else if cfg.MonitorInterval > 60 {
		log.Logger.Warn("MonitorInterval[%d] > 60, use 60", cfg.MonitorInterval)
		cfg.MonitorInterval = 60
	} else {
		if 60%cfg.MonitorInterval > 0 {
			return fmt.Errorf("MonitorInterval[%d] can not divide 60", cfg.MonitorInterval)
		}

		if cfg.MonitorInterval < 20 {
			return fmt.Errorf("MonitorInterval[%d] is too small(<20)", cfg.MonitorInterval)
		}
	}

	// check MaxHeaderUriBytes
	if cfg.MaxHeaderUriBytes <= 0 {
		return fmt.Errorf("MaxHeaderUriBytes[%d] should > 0", cfg.MaxHeaderUriBytes)
	}

	// check MaxHeaderBytes
	if cfg.MaxHeaderBytes <= 0 {
		return fmt.Errorf("MaxHeaderHeaderBytes[%d] should > 0", cfg.MaxHeaderBytes)
	}

	// check Plugins
	if err := checkPlugins(cfg); err != nil {
		return fmt.Errorf("plugins[%v] check failed. err: %s", cfg.Plugins, err.Error())
	}

	return nil
}

// 负载均衡
func checkLayer4LoadBalancer(cfg *ConfigBasic) error {
	if len(cfg.Layer4LoadBalancer) == 0 {
		cfg.Layer4LoadBalancer = BalancerNone // default NONE
	}

	switch cfg.Layer4LoadBalancer {
	case BalancerProxy:
		return nil
	case BalancerNone:
		return nil
	default:
		return fmt.Errorf("Layer4LoadBalancer[%s] should be PROXY/NONE", cfg.Layer4LoadBalancer)
	}
}

func checkPlugins(cfg *ConfigBasic) error {
	plugins := []string{}
	for _, pluginPath := range cfg.Plugins {
		pluginPath = strings.TrimSpace(pluginPath)
		if pluginPath == "" {
			continue
		}

		if !strings.HasSuffix(pluginPath, LibrarySuffix) {
			pluginPath += LibrarySuffix
		}
		plugins = append(plugins, pluginPath)
	}
	cfg.Plugins = plugins

	return nil
}

func dataFileConfCheck(cfg *ConfigBasic, confRoot string) error {
	// check HostRuleConf
	if cfg.HostRuleConf == "" {
		cfg.HostRuleConf = "server_data_conf/host_rule.data"
		log.Logger.Warn("HostRuleConf not set, use default value [%s]", cfg.HostRuleConf)
	}
	cfg.HostRuleConf = bfe_util.ConfPathProc(cfg.HostRuleConf, confRoot)

	// check VipRuleConf
	if cfg.VipRuleConf == "" {
		cfg.VipRuleConf = "server_data_conf/vip_rule.data"
		log.Logger.Warn("VipRuleConf not set, use default value [%s]", cfg.VipRuleConf)
	}
	cfg.VipRuleConf = bfe_util.ConfPathProc(cfg.VipRuleConf, confRoot)

	// check RouteRuleConf
	if cfg.RouteRuleConf == "" {
		cfg.RouteRuleConf = "server_data_conf/route_rule.data"
		log.Logger.Warn("RouteRuleConf not set, use default value [%s]", cfg.RouteRuleConf)
	}
	cfg.RouteRuleConf = bfe_util.ConfPathProc(cfg.RouteRuleConf, confRoot)

	// check ClusterTableConf
	if cfg.ClusterTableConf == "" {
		cfg.ClusterTableConf = "cluster_conf/cluster_table.data"
		log.Logger.Warn("ClusterTableConf not set, use default value [%s]", cfg.ClusterTableConf)
	}
	cfg.ClusterTableConf = bfe_util.ConfPathProc(cfg.ClusterTableConf, confRoot)

	// check GslbConf
	if cfg.GslbConf == "" {
		cfg.GslbConf = "cluster_conf/gslb.data"
		log.Logger.Warn("GslbConf not set, use default value [%s]", cfg.GslbConf)
	}
	cfg.GslbConf = bfe_util.ConfPathProc(cfg.GslbConf, confRoot)

	// check ClusterConf
	if cfg.ClusterConf == "" {
		cfg.ClusterConf = "server_data_conf/cluster_conf.data"
		log.Logger.Warn("ClusterConf not set, use default value [%s]", cfg.ClusterConf)
	}
	cfg.ClusterConf = bfe_util.ConfPathProc(cfg.ClusterConf, confRoot)

	// check NameConf (optional)
	if cfg.NameConf == "" {
		log.Logger.Warn("NameConf not set, ignore optional name conf")
	} else {
		cfg.NameConf = bfe_util.ConfPathProc(cfg.NameConf, confRoot)
	}

	return nil
}
