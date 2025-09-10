// Copyright 2023 The frp Authors // // Licensed under the Apache License, Version 2.0 (the "License"); // you may not use this file except in compliance with the License. // You may obtain a copy of the License at // // http://www.apache.org/licenses/LICENSE-2.0 // // Unless required by applicable law or agreed to in writing, software // distributed under the License is distributed on an "AS IS" BASIS, // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. // See the License for the specific language governing permissions and // limitations under the License.
package legacy

import (
"fmt"
"net"
"os"
"path/filepath"
"slices"
"strconv"
"strings"
"sync"

"github.com/miekg/dns"
"gopkg.in/ini.v1"

legacyauth "github.com/fatedier/frp/pkg/auth/legacy"
"github.com/fatedier/frp/pkg/util/util"
)

//-------------------------- 客户端配置相关（新增 / 修改部分）--------------------------
// ClientCommonConf 客户端配置结构体（含 TXT 动态刷新字段）
type ClientCommonConf struct {
legacyauth.ClientConfig ini:",extends"

// 原有客户端配置字段
ServerAddr string ini:"server_addr" json:"server_addr"
ServerPort int ini:"server_port" json:"server_port"
NatHoleSTUNServer string ini:"nat_hole_stun_server" json:"nat_hole_stun_server"
DialServerTimeout int64 ini:"dial_server_timeout" json:"dial_server_timeout"
DialServerKeepAlive int64 ini:"dial_server_keepalive" json:"dial_server_keepalive"
ConnectServerLocalIP string ini:"connect_server_local_ip" json:"connect_server_local_ip"
HTTPProxy string ini:"http_proxy" json:"http_proxy"
LogFile string ini:"log_file" json:"log_file"
LogWay string ini:"log_way" json:"log_way"
LogLevel string ini:"log_level" json:"log_level"
LogMaxDays int64 ini:"log_max_days" json:"log_max_days"
DisableLogColor bool ini:"disable_log_color" json:"disable_log_color"
AdminAddr string ini:"admin_addr" json:"admin_addr"
AdminPort int ini:"admin_port" json:"admin_port"
AdminUser string ini:"admin_user" json:"admin_user"
AdminPwd string ini:"admin_pwd" json:"admin_pwd"
AssetsDir string ini:"assets_dir" json:"assets_dir"
PoolCount int ini:"pool_count" json:"pool_count"
TCPMux bool ini:"tcp_mux" json:"tcp_mux"
TCPMuxKeepaliveInterval int64 ini:"tcp_mux_keepalive_interval" json:"tcp_mux_keepalive_interval"
User string ini:"user" json:"user"
DNSServer string ini:"dns_server" json:"dns_server"
LoginFailExit bool ini:"login_fail_exit" json:"login_fail_exit"
Start []string ini:"start" json:"start"
Protocol string ini:"protocol" json:"protocol"
QUICKeepalivePeriod int ini:"quic_keepalive_period" json:"quic_keepalive_period"
QUICMaxIdleTimeout int ini:"quic_max_idle_timeout" json:"quic_max_idle_timeout"
QUICMaxIncomingStreams int ini:"quic_max_incoming_streams" json:"quic_max_incoming_streams"
TLSEnable bool ini:"tls_enable" json:"tls_enable"
TLSCertFile string ini:"tls_cert_file" json:"tls_cert_file"
TLSKeyFile string ini:"tls_key_file" json:"tls_key_file"
TLSTrustedCaFile string ini:"tls_trusted_ca_file" json:"tls_trusted_ca_file"
TLSServerName string ini:"tls_server_name" json:"tls_server_name"
DisableCustomTLSFirstByte bool ini:"disable_custom_tls_first_byte" json:"disable_custom_tls_first_byte"
HeartbeatInterval int64 ini:"heartbeat_interval" json:"heartbeat_interval"
HeartbeatTimeout int64 ini:"heartbeat_timeout" json:"heartbeat_timeout"
Metas map[string]string ini:"-" json:"metas"
UDPPacketSize int64 ini:"udp_packet_size" json:"udp_packet_size"
IncludeConfigFiles []string ini:"includes" json:"includes"
PprofEnable bool ini:"pprof_enable" json:"pprof_enable"

// 新增：TXT 记录动态刷新相关字段
TXTRefreshInterval int64 ini:"txt_refresh_interval" json:"txt_refresh_interval" // 刷新间隔（秒），0 = 关闭
CurrentServerAddr string ini:"-" json:"-" // 当前使用的服务器地址（内存变量，不持久化）
CurrentServerPort int ini:"-" json:"-" // 当前使用的服务器端口（内存变量，不持久化）
Mu sync.RWMutex ini:"-" json:"-" // 并发安全锁（保护地址字段读写）
}

// GetDefaultClientConf 获取客户端默认配置（初始化新增的 TXT 刷新字段）
func GetDefaultClientConf () ClientCommonConf {
return ClientCommonConf {
ClientConfig: legacyauth.GetDefaultClientConf (),
TCPMux: true,
LoginFailExit: true,
Protocol: "tcp",
Start: make ([] string, 0),
TLSEnable: true,
DisableCustomTLSFirstByte: true,
Metas: make (map [string] string),
IncludeConfigFiles: make ([] string, 0),
TXTRefreshInterval: 0, // 默认关闭 TXT 动态刷新
}
}

// UnmarshalClientConfFromIni 解析客户端 INI 配置（含 TXT 记录解析）
func UnmarshalClientConfFromIni (source any) (ClientCommonConf, error) {
f, err := ini.LoadSources (ini.LoadOptions {
Insensitive: false,
InsensitiveSections: false,
InsensitiveKeys: false,
IgnoreInlineComment: true,
AllowBooleanKeys: true,
}, source)
if err != nil {
return ClientCommonConf {}, err
}

s, err := f.GetSection("common")
if err != nil {
return ClientCommonConf{}, fmt.Errorf("invalid configuration file, not found [common] section")
}

common := GetDefaultClientConf()
err = s.MapTo(&common)
if err != nil {
return ClientCommonConf{}, err
}

// 核心：解析 server_addr（支持 txt:// 前缀）
resolvedAddr, resolvedPort, err := ResolveServerAddr (common.ServerAddr, common.DNSServer)
if err != nil {
return ClientCommonConf {}, fmt.Errorf ("resolve server address failed: % v", err)
}
// 更新解析后的地址和端口（配置中未指定 ServerPort 时用解析结果）
common.ServerAddr = resolvedAddr
if common.ServerPort == 0 {
common.ServerPort = resolvedPort
}
// 初始化当前地址（用于后续动态刷新对比）
common.CurrentServerAddr = resolvedAddr
common.CurrentServerPort = resolvedPort

// 原有逻辑：解析 metas 和 oidc 参数
common.Metas = GetMapWithoutPrefix (s.KeysHash (), "meta_")
common.OidcAdditionalEndpointParams = GetMapWithoutPrefix (s.KeysHash (), "oidc_additional_")

return common, nil
}

// ResolveServerAddr 解析服务器地址（支持 txt:// 前缀）
// 参数：addr - 配置中的 server_addr，dnsServer - 客户端配置的 dns_server（优先使用）
func ResolveServerAddr (addr, dnsServer string) (string, int, error) {
// 处理 txt:// 前缀
if strings.HasPrefix (addr, "txt://") {
domain := strings.TrimPrefix (addr, "txt://")
return resolveFromTXT (domain, dnsServer)
}

// 原有逻辑：处理普通地址（host:port 或 仅 host）
host, portStr, err := net.SplitHostPort (addr)
if err != nil {
// 未指定端口，返回 host + 默认端口 7000
return addr, 7000, nil
}
port, err := strconv.Atoi (portStr)
if err != nil {
return "", 0, fmt.Errorf ("invalid port: % s", portStr)
}
return host, port, nil
}

//resolveFromTXT 从 DNS TXT 记录解析服务器地址（格式：host:port）
func resolveFromTXT (domain, dnsServer string) (string, int, error) {
resolver := dns.Client {}
msg := dns.Msg {}
msg.SetQuestion (dns.Fqdn (domain), dns.TypeTXT)

// 优先使用客户端配置的 DNS 服务器，否则用默认（8.8.8.8:53）
dnsAddr := "8.8.8.8:53"
if dnsServer != "" {
// 补全 DNS 端口（未指定时默认 53）
if _, _, err := net.SplitHostPort (dnsServer); err != nil {
dnsAddr = fmt.Sprintf ("% s:53", dnsServer)
} else {
dnsAddr = dnsServer
}
}

// 发送 DNS 查询
r, _, err := resolver.Exchange (&msg, dnsAddr)
if err != nil {
return "", 0, fmt.Errorf ("dns query failed (server: % s): % v", dnsAddr, err)
}

// 检查 TXT 记录是否存在
if len (r.Answer) == 0 {
return "", 0, fmt.Errorf ("no TXT records found for domain: % s", domain)
}

// 解析 TXT 记录（取第一条符合格式的记录）
for _, ans := range r.Answer {
txtRecord, ok := ans.(*dns.TXT)
if !ok {
continue
}
for _, txt := range txtRecord.Txt {
parts := strings.Split (txt, ":")
if len (parts) != 2 {
continue // 格式错误，跳过该记录
}
host := parts [0]
port, err := strconv.Atoi (parts [1])
if err != nil {
continue // 端口不是数字，跳过
}
// 验证端口有效性（1-65535）
if port < 1 || port > 65535 {
continue
}
return host, port, nil
}
}

return "", 0, fmt.Errorf("no valid TXT record (format: host:port) found for domain: %s", domain)
}

// ValidateClientConf 客户端配置验证（新增 TXT 刷新间隔验证）
func (cfg *ClientCommonConf) ValidateClientConf () error {
// 原有验证逻辑
if cfg.HeartbeatTimeout > 0 && cfg.HeartbeatInterval > 0 {
if cfg.HeartbeatTimeout < cfg.HeartbeatInterval {
return fmt.Errorf ("heartbeat_timeout (% d) must be >= heartbeat_interval (% d)", cfg.HeartbeatTimeout, cfg.HeartbeatInterval)
}
}

if !cfg.TLSEnable {
if cfg.TLSCertFile != "" {
fmt.Println("WARNING! tls_cert_file is invalid when tls_enable is false")
}
if cfg.TLSKeyFile != "" {
fmt.Println("WARNING! tls_key_file is invalid when tls_enable is false")
}
if cfg.TLSTrustedCaFile != "" {
fmt.Println("WARNING! tls_trusted_ca_file is invalid when tls_enable is false")
}
}

if !slices.Contains([]string{"tcp", "kcp", "quic", "websocket", "wss"}, cfg.Protocol) {
return fmt.Errorf("invalid protocol: %s (supported: tcp, kcp, quic, websocket, wss)", cfg.Protocol)
}

for _, f := range cfg.IncludeConfigFiles {
absDir, err := filepath.Abs(filepath.Dir(f))
if err != nil {
return fmt.Errorf("include file directory parse failed: %s, err: %v", f, err)
}
if _, err := os.Stat(absDir); os.IsNotExist(err) {
return fmt.Errorf("include file directory not exist: %s", absDir)
}
}

// 新增：TXT 刷新间隔验证（必须 >=0）
if cfg.TXTRefreshInterval < 0 {
return fmt.Errorf ("txt_refresh_interval must be>= 0 (current: % d)", cfg.TXTRefreshInterval)
}

return nil
}

//-------------------------- 服务器端配置相关（原有代码，无修改）--------------------------
type HTTPPluginOptions struct {
Name string ini:"name"
Addr string ini:"addr"
Path string ini:"path"
Ops []string ini:"ops"
TLSVerify bool ini:"tlsVerify"
}

// ServerCommonConf 服务器端配置结构体（原有逻辑完全保留）
type ServerCommonConf struct {
legacyauth.ServerConfig ini:",extends"

BindAddr string ini:"bind_addr" json:"bind_addr"
BindPort int ini:"bind_port" json:"bind_port"
KCPBindPort int ini:"kcp_bind_port" json:"kcp_bind_port"
QUICBindPort int ini:"quic_bind_port" json:"quic_bind_port"
QUICKeepalivePeriod int ini:"quic_keepalive_period" json:"quic_keepalive_period"
QUICMaxIdleTimeout int ini:"quic_max_idle_timeout" json:"quic_max_idle_timeout"
QUICMaxIncomingStreams int ini:"quic_max_incoming_streams" json:"quic_max_incoming_streams"
ProxyBindAddr string ini:"proxy_bind_addr" json:"proxy_bind_addr"
VhostHTTPPort int ini:"vhost_http_port" json:"vhost_http_port"
VhostHTTPSPort int ini:"vhost_https_port" json:"vhost_https_port"
TCPMuxHTTPConnectPort int ini:"tcpmux_httpconnect_port" json:"tcpmux_httpconnect_port"
TCPMuxPassthrough bool ini:"tcpmux_passthrough" json:"tcpmux_passthrough"
VhostHTTPTimeout int64 ini:"vhost_http_timeout" json:"vhost_http_timeout"
DashboardAddr string ini:"dashboard_addr" json:"dashboard_addr"
DashboardPort int ini:"dashboard_port" json:"dashboard_port"
DashboardTLSCertFile string ini:"dashboard_tls_cert_file" json:"dashboard_tls_cert_file"
DashboardTLSKeyFile string ini:"dashboard_tls_key_file" json:"dashboard_tls_key_file"
DashboardTLSMode bool ini:"dashboard_tls_mode" json:"dashboard_tls_mode"
DashboardUser string ini:"dashboard_user" json:"dashboard_user"
DashboardPwd string ini:"dashboard_pwd" json:"dashboard_pwd"
EnablePrometheus bool ini:"enable_prometheus" json:"enable_prometheus"
AssetsDir string ini:"assets_dir" json:"assets_dir"
LogFile string ini:"log_file" json:"log_file"
LogWay string ini:"log_way" json:"log_way"
LogLevel string ini:"log_level" json:"log_level"
LogMaxDays int64 ini:"log_max_days" json:"log_max_days"
DisableLogColor bool ini:"disable_log_color" json:"disable_log_color"
DetailedErrorsToClient bool ini:"detailed_errors_to_client" json:"detailed_errors_to_client"
SubDomainHost string ini:"subdomain_host" json:"subdomain_host"
TCPMux bool ini:"tcp_mux" json:"tcp_mux"
TCPMuxKeepaliveInterval int64 ini:"tcp_mux_keepalive_interval" json:"tcp_mux_keepalive_interval"
TCPKeepAlive int64 ini:"tcp_keepalive" json:"tcp_keepalive"
Custom404Page string ini:"custom_404_page" json:"custom_404_page"
AllowPorts map[int]struct{} ini:"-" json:"-"
AllowPortsStr string ini:"-" json:"-"
MaxPoolCount int64 ini:"max_pool_count" json:"max_pool_count"
MaxPortsPerClient int64 ini:"max_ports_per_client" json:"max_ports_per_client"
TLSOnly bool ini:"tls_only" json:"tls_only"
TLSCertFile string ini:"tls_cert_file" json:"tls_cert_file"
TLSKeyFile string ini:"tls_key_file" json:"tls_key_file"
TLSTrustedCaFile string ini:"tls_trusted_ca_file" json:"tls_trusted_ca_file"
HeartbeatTimeout int64 ini:"heartbeat_timeout" json:"heartbeat_timeout"
UserConnTimeout int64 ini:"user_conn_timeout" json:"user_conn_timeout"
HTTPPlugins map[string]HTTPPluginOptions ini:"-" json:"http_plugins"
UDPPacketSize int64 ini:"udp_packet_size" json:"udp_packet_size"
PprofEnable bool ini:"pprof_enable" json:"pprof_enable"
NatHoleAnalysisDataReserveHours int64 ini:"nat_hole_analysis_data_reserve_hours" json:"nat_hole_analysis_data_reserve_hours"
}

// GetDefaultServerConf 服务器端默认配置（原有逻辑）
func GetDefaultServerConf () ServerCommonConf {
return ServerCommonConf {
ServerConfig: legacyauth.GetDefaultServerConf (),
DashboardAddr: "0.0.0.0",
LogFile: "console",
LogWay: "console",
DetailedErrorsToClient: true,
TCPMux: true,
AllowPorts: make (map [int] struct {}),
HTTPPlugins: make (map [string] HTTPPluginOptions),
}
}

// UnmarshalServerConfFromIni 解析服务器端 INI 配置（原有逻辑）
func UnmarshalServerConfFromIni (source any) (ServerCommonConf, error) {
f, err := ini.LoadSources (ini.LoadOptions {
Insensitive: false,
InsensitiveSections: false,
InsensitiveKeys: false,
IgnoreInlineComment: true,
AllowBooleanKeys: true,
}, source)
if err != nil {
return ServerCommonConf {}, err
}

s, err := f.GetSection("common")
if err != nil {
return ServerCommonConf{}, fmt.Errorf("invalid configuration file, not found [common] section")
}

common := GetDefaultServerConf()
err = s.MapTo(&common)
if err != nil {
return ServerCommonConf{}, err
}

// 原有逻辑：解析 allow_ports
allowPortStr := s.Key ("allow_ports").String ()
if allowPortStr != "" {
common.AllowPortsStr = allowPortStr
}

// 原有逻辑：解析 plugin.xxx 配置
pluginOpts := make (map [string] HTTPPluginOptions)
for _, section := range f.Sections () {
name := section.Name ()
if !strings.HasPrefix (name, "plugin.") {
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

//loadHTTPPluginOpt 加载 HTTP 插件配置（原有逻辑）
func loadHTTPPluginOpt (section *ini.Section) (*HTTPPluginOptions, error) {
name := strings.TrimSpace (strings.TrimPrefix (section.Name (), "plugin."))

opt := &HTTPPluginOptions{}
err := section.MapTo(opt)
if err != nil {
return nil, err
}

opt.Name = name

return opt, nil
}

//-------------------------- 通用工具函数（原有逻辑）--------------------------
// GetMapWithoutPrefix 从 INI 键值对中提取前缀匹配的字段（用于 metas/oidc 参数）
func GetMapWithoutPrefix (m map [string] string, prefix string) map [string] string {
res := make (map [string] string)
for k, v := range m {
if strings.HasPrefix (k, prefix) {
res [strings.TrimPrefix (k, prefix)] = v
}
}
return res
}
