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

package mod_access

import (
	"fmt"
)

import (
	gcfg "gopkg.in/gcfg.v1"
)

import (
	"github.com/bfenetworks/bfe/bfe_util/access_log"
)

// ConfModAccess holds the config of access module.
// 配置文件映射
type ConfModAccess struct {
	Log access_log.LogConfig

	// 日志记录模板
	Template struct {
		// 请求日志模板
		RequestTemplate string // access log format string
		// 会话日志模板
		SessionTemplate string // session finish log format string
	}
}

// ConfLoad loads config of access module from file.
// 从文件中加载访问模块的配置。
func ConfLoad(filePath string, confRoot string) (*ConfModAccess, error) {
	var err error
	var cfg ConfModAccess

	err = gcfg.ReadFileInto(&cfg, filePath)
	if err != nil {
		return &cfg, err
	}

	// 校验
	err = cfg.Check(confRoot)
	if err != nil {
		return &cfg, err
	}

	// 转换
	cfg.Convert()

	return &cfg, nil
}

// Check 配置校验
func (cfg *ConfModAccess) Check(confRoot string) error {
	err := cfg.Log.Check(confRoot)
	if err != nil {
		return err
	}

	if cfg.Template.RequestTemplate == "" {
		return fmt.Errorf("ModAccess.RequestTemplate not set")
	}

	if cfg.Template.SessionTemplate == "" {
		return fmt.Errorf("ModAccess.SessionTemplate not set")
	}
	return nil
}

// Convert 默认日志模板
func (cfg *ConfModAccess) Convert() {
	switch cfg.Template.RequestTemplate {
	case "COMMON":
		cfg.Template.RequestTemplate = "$host - - $request_time \"$request_line\" $status_code $res_len"
	case "COMBINED":
		cfg.Template.RequestTemplate = "$host - - $request_time \"$request_line\" $status_code $res_len \"${Referer}req_header\" \"${User-Agent}req_header\""
	}
}

// 校验logFmtItem项
func checkLogFmt(item LogFmtItem, logFmtType string) error {
	if logFmtType != Request && logFmtType != Session {
		return fmt.Errorf("logFmtType should be Request or Session")
	}

	domain, found := fmtItemDomainTable[item.Type]
	if !found {
		return fmt.Errorf("type : (%d, %s) not configured in domain table",
			item.Type, item.Key)
	}

	// 校验作用域
	if domain != DomainAll && domain != logFmtType {
		return fmt.Errorf("type : (%d, %s) should not in request finish log",
			item.Type, item.Key)
	}

	return nil
}

// offset后面的值是否在fmtTable中
func tokenTypeGet(templatePtr *string, offset int) (int, int, error) {
	templateLen := len(*templatePtr)

	for key, logItemType := range fmtTable {
		n := len(key)
		if offset+n > templateLen {
			continue
		}

		if key == (*templatePtr)[offset:(offset+n)] {
			return logItemType, offset + n - 1, nil
		}
	}

	return -1, -1, fmt.Errorf("no such log item format type : %s", *templatePtr)
}

// 找到{}中间的内容User-Agent以及req_header的类型
// ${User-Agent}req_header
func parseBracketToken(templatePtr *string, offset int) (LogFmtItem, int, error) {
	length := len(*templatePtr)

	var endOfBracket int
	for endOfBracket = offset + 1; endOfBracket < length; endOfBracket++ {
		if (*templatePtr)[endOfBracket] == '}' {
			break
		}
	}

	// 找不到}
	if endOfBracket >= length {
		return LogFmtItem{}, -1, fmt.Errorf("log format: { must be terminated by a }")
	}

	// }不能是最后一个字符
	if endOfBracket == (length - 1) {
		return LogFmtItem{}, -1, fmt.Errorf("log format: } must followed a character")
	}

	key := (*templatePtr)[offset+1 : endOfBracket]

	logItemType, end, err := tokenTypeGet(templatePtr, endOfBracket+1)
	if err != nil {
		return LogFmtItem{}, -1, err
	}

	return LogFmtItem{key, logItemType}, end, nil
}

// "REQUEST_LOG $time clientip: $remote_addr serverip: $server_addr host: $host product: $product user_agent: ${User-Agent}req_header status: $status_code error: $error"
func parseLogTemplate(logTemplate string) ([]LogFmtItem, error) {
	reqFmts := []LogFmtItem{}

	start := 0
	templateLen := len(logTemplate)
	var token string

	for i := 0; i < templateLen; i++ {
		// 非$跳过
		if logTemplate[i] != '$' {
			continue
		}

		// 最后一个字符是$
		if (i + 1) == templateLen {
			return nil, fmt.Errorf("log format: $ must followed with a character")
		}

		// 开头字符串
		if start <= (i - 1) {
			token = logTemplate[start:i]
			item := LogFmtItem{token, FormatString}
			reqFmts = append(reqFmts, item)
		}

		//${User-Agent}req_header 从http的head头里取出来User-Agent
		if logTemplate[i+1] == '{' {
			item, end, err := parseBracketToken(&logTemplate, i+1)
			if err != nil {
				return nil, err
			}
			reqFmts = append(reqFmts, item)
			i = end
			start = end + 1

		} else {
			// $remote_addr
			logItemType, end, err := tokenTypeGet(&logTemplate, i+1)
			if err != nil {
				return nil, err
			}

			token = logTemplate[(i + 1) : end+1]
			item := LogFmtItem{token, logItemType}
			reqFmts = append(reqFmts, item)

			i = end
			start = end + 1
		}
	}

	// 最后剩余字符
	if start < templateLen {
		token = logTemplate[start:templateLen]
		item := LogFmtItem{token, FormatString}
		reqFmts = append(reqFmts, item)
	}

	return reqFmts, nil
}
