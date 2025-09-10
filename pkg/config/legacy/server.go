// Copyright 2023 The frp Authors
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

package legacy

import (
	"strings"

	"gopkg.in/ini.v1" // 确保导入ini包，且格式正确

	legacyauth "github.com/fatedier/frp/pkg/auth/legacy"
)

// -------------------------- 1. 修复HTTPPluginOptions结构体标签格式 --------------------------
type HTTPPluginOptions struct {
	Name      string   `ini:"name"`      // 标签用反引号包裹，字段类型与标签间有空格
	Addr      string   `ini:"addr"`      // 格式：字段名 类型 `标签`
	Path      string   `ini:"path"`
	Ops       []string `ini:"ops"`
	TLSVerify bool     `ini:"tlsVerify"`
}

// -------------------------- 2. 修复ServerCommonConf结构体（核心错误点） --------------------------
// ServerCommonConf 服务器端配置结构体（修正所有标签格式和代码闭合）
type ServerCommonConf struct {
	legacyauth.ServerConfig `ini:",extends"` // 正确的嵌入标签格式

	// 所有字段标签均修正为：`ini:"xxx" json:"xxx"`，确保反引号、空格正确
	BindAddr string `ini:"bind_addr" json:"bind_addr"`
	BindPort int    `ini:"bind_port" json:"bind_port"`
	KCPBindPort int `ini:"kcp_bind_port" json:"kcp_bind_port"`
	QUICBindPort int `ini:"quic_bind_port" json:"quic_bind_port"`
	QUICKeepalivePeriod    int `ini:"quic_keepalive_period" json:"quic_keepalive_period"`
	QUICMaxIdleTimeout     int `ini:"quic_max_idle_timeout" json:"quic_max_idle_timeout"`
	QUICMaxIncomingStreams int `ini:"quic_max_incoming_streams" json:"quic_max_incoming_streams"`
	ProxyBindAddr string `ini:"proxy_bind_addr" json:"proxy_bind_addr"`
	VhostHTTPPort int `ini:"vhost_http_port" json:"vhost_http_port"`
	VhostHTTPSPort int `ini:"vhost_https_port" json:"vhost_https_port"`
	TCPMuxHTTPConnectPort int `ini:"tcpmux_httpconnect_port" json:"tcpmux_httpconnect_port"`
	TCPMuxPassthrough bool `ini:"tcpmux_passthrough" json:"tcpmux_passthrough"`
	VhostHTTPTimeout int64 `ini:"vhost_http_timeout" json:"vhost_http_timeout"`
	DashboardAddr string `ini:"dashboard_addr" json:"dashboard_addr"`
	DashboardPort int `ini:"dashboard_port" json:"dashboard_port"`
	DashboardTLSCertFile string `ini:"dashboard_tls_cert_file" json:"dashboard_tls_cert_file"`
	DashboardTLSKeyFile string `ini:"dashboard_tls_key_file" json:"dashboard_tls_key_file"`
	DashboardTLSMode bool `ini:"dashboard_tls_mode" json:"dashboard_tls_mode"`
	DashboardUser string `ini:"dashboard_user" json:"dashboard_user"`
	DashboardPwd string `ini:"dashboard_pwd" json:"dashboard_pwd"`
	EnablePrometheus bool `ini:"enable_prometheus" json:"enable_prometheus"`
	AssetsDir string `ini:"assets_dir" json:"assets_dir"`
	LogFile string `ini:"log_file" json:"log_file"`
	LogWay string `ini:"log_way" json:"log_way"`
	LogLevel string `ini:"log_level" json:"log_level"`
	LogMaxDays int64 `ini:"log_max_days" json:"log_max_days"`
	DisableLogColor bool `ini:"disable_log_color" json:"disable_log_color"`
	DetailedErrorsToClient bool `ini:"detailed_errors_to_client" json:"detailed_errors_to_client"`
	SubDomainHost string `ini:"subdomain_host" json:"subdomain_host"`
	TCPMux bool `ini:"tcp_mux" json:"tcp_mux"`
	TCPMuxKeepaliveInterval int64 `ini:"tcp_mux_keepalive_interval" json:"tcp_mux_keepalive_interval"`
	TCPKeepAlive int64 `ini:"tcp_keepalive" json:"tcp_keepalive"`
	Custom404Page string `ini:"custom_404_page" json:"custom_404_page"`
	AllowPorts map[int]struct{} `ini:"-" json:"-"` // 忽略ini解析的标签格式
	AllowPortsStr string `ini:"-" json:"-"`
	MaxPoolCount int64 `ini:"max_pool_count" json:"max_pool_count"`
	MaxPortsPerClient int64 `ini:"max_ports_per_client" json:"max_ports_per_client"`
	TLSOnly bool `ini:"tls_only" json:"tls_only"`
	TLSCertFile string `ini:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile string `ini:"tls_key_file" json:"tls_key_file"`
	TLSTrustedCaFile string `ini:"tls_trusted_ca_file" json:"tls_trusted_ca_file"`
	HeartbeatTimeout int64 `ini:"heartbeat_timeout" json:"heartbeat_timeout"`
	UserConnTimeout int64 `ini:"user_conn_timeout" json:"user_conn_timeout"`
	HTTPPlugins map[string]HTTPPluginOptions `ini:"-" json:"http_plugins"`
	UDPPacketSize int64 `ini:"udp_packet_size" json:"udp_packet_size"`
	PprofEnable bool `ini:"pprof_enable" json:"pprof_enable"`
	NatHoleAnalysisDataReserveHours int64 `ini:"nat_hole_analysis_data_reserve_hours" json:"nat_hole_analysis_data_reserve_hours"`
}

// -------------------------- 3. 修复GetDefaultServerConf函数（确保代码闭合） --------------------------
func GetDefaultServerConf() ServerCommonConf {
	return ServerCommonConf{
		ServerConfig:           legacyauth.GetDefaultServerConf(),
		DashboardAddr:          "0.0.0.0",
		LogFile:                "console",
		LogWay:                 "console",
		DetailedErrorsToClient: true,
		TCPMux:                 true,
		AllowPorts:             make(map[int]struct{}), // 切片/映射初始化语法正确
		HTTPPlugins:            make(map[string]HTTPPluginOptions),
	}
}

// -------------------------- 4. 修复UnmarshalServerConfFromIni函数（标签解析逻辑） --------------------------
func UnmarshalServerConfFromIni(source any) (ServerCommonConf, error) {
	// 修复ini.LoadSources的参数格式（确保LoadOptions正确）
	f, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:         false,
		InsensitiveSections: false,
		InsensitiveKeys:     false,
		IgnoreInlineComment: true,
		AllowBooleanKeys:    true,
	}, source)
	if err != nil {
		return ServerCommonConf{}, err
	}

	s, err := f.GetSection("common")
	if err != nil {
		return ServerCommonConf{}, err
	}

	common := GetDefaultServerConf()
	// 修复MapTo的调用（确保结构体标签可被ini包识别）
	if err := s.MapTo(&common); err != nil {
		return ServerCommonConf{}, err
	}

	// 修复allow_ports解析逻辑（确保变量赋值正确）
	allowPortStr := s.Key("allow_ports").String()
	if allowPortStr != "" {
		common.AllowPortsStr = allowPortStr
	}

	// 修复HTTPPlugins解析（确保循环和赋值语法正确）
	pluginOpts := make(map[string]HTTPPluginOptions)
	for _, section := range f.Sections() {
		name := section.Name()
		if !strings.HasPrefix(name, "plugin.") {
			continue
		}

		opt, err := loadHTTPPluginOpt(section)
		if err != nil {
			return ServerCommonConf{}, err
		}

		pluginOpts[opt.Name] = *opt
	}
	common.HTTPPlugins = pluginOpts

	return common, nil
}

// -------------------------- 5. 修复loadHTTPPluginOpt函数（确保结构体标签匹配） --------------------------
func loadHTTPPluginOpt(section *ini.Section) (*HTTPPluginOptions, error) {
	name := strings.TrimSpace(strings.TrimPrefix(section.Name(), "plugin."))

	opt := &HTTPPluginOptions{}
	// 修复MapTo调用（确保HTTPPluginOptions的标签正确）
	if err := section.MapTo(opt); err != nil {
		return nil, err
	}

	opt.Name = name
	return opt, nil
}
