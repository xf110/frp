package legacy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync" // 1. 新增：导入sync包，解决undefined: sync

	"github.com/miekg/dns"
	"gopkg.in/ini.v1"

	legacyauth "github.com/fatedier/frp/pkg/auth/legacy"
	"github.com/fatedier/frp/pkg/util/util"
)

// 2. 修正：函数增加dnsServer参数，支持使用客户端配置的DNS服务器（而非硬编码8.8.8.8）
func resolveServerAddr(addr, dnsServer string) (string, int, error) {
	if strings.HasPrefix(addr, "txt://") {
		domain := strings.TrimPrefix(addr, "txt://")
		return resolveFromTXT(domain, dnsServer) // 传DNS服务器参数
	}

	// 原有普通地址解析逻辑
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 7000, nil // 未指定端口时用默认7000
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s", portStr)
	}
	return host, port, nil
}

// 3. 修正：接收dnsServer参数，优先使用客户端配置的DNS
func resolveFromTXT(domain, dnsServer string) (string, int, error) {
	resolver := dns.Client{}
	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)

	// 优先用客户端配置的DNS，否则用默认8.8.8.8:53
	dnsAddr := "8.8.8.8:53"
	if dnsServer != "" {
		// 补全DNS端口（未指定时默认53）
		if _, _, err := net.SplitHostPort(dnsServer); err != nil {
			dnsAddr = fmt.Sprintf("%s:53", dnsServer)
		} else {
			dnsAddr = dnsServer
		}
	}

	// 发送DNS查询
	r, _, err := resolver.Exchange(&msg, dnsAddr)
	if err != nil {
		return "", 0, fmt.Errorf("dns query failed (server: %s): %v", dnsAddr, err)
	}

	if len(r.Answer) == 0 {
		return "", 0, fmt.Errorf("no TXT records found for domain: %s", domain)
	}

	// 解析TXT记录（格式：host:port）
	for _, ans := range r.Answer {
		txtRecord, ok := ans.(*dns.TXT)
		if !ok {
			continue
		}
		for _, txt := range txtRecord.Txt {
			parts := strings.Split(txt, ":")
			if len(parts) != 2 {
				continue
			}
			host := parts[0]
			port, err := strconv.Atoi(parts[1])
			if err != nil || port < 1 || port > 65535 {
				continue // 端口无效，跳过
			}
			return host, port, nil
		}
	}

	return "", 0, fmt.Errorf("no valid TXT record (format: host:port) for domain: %s", domain)
}

func UnmarshalClientConfFromIni(source any) (ClientCommonConf, error) {
	f, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:         false,
		InsensitiveSections: false,
		InsensitiveKeys:     false,
		IgnoreInlineComment: true,
		AllowBooleanKeys:    true,
	}, source)
	if err != nil {
		return ClientCommonConf{}, err
	}

	s, err := f.GetSection("common")
	if err != nil {
		return ClientCommonConf{}, fmt.Errorf("invalid config: missing [common] section")
	}

	common := GetDefaultClientConf()
	if err := s.MapTo(&common); err != nil {
		return ClientCommonConf{}, err
	}

	// 4. 修正：调用resolveServerAddr时传入客户端配置的DNSServer
	resolvedHost, resolvedPort, err := resolveServerAddr(common.ServerAddr, common.DNSServer)
	if err != nil {
		return ClientCommonConf{}, fmt.Errorf("resolve server addr failed: %v", err)
	}
	common.ServerAddr = resolvedHost
	if common.ServerPort == 0 {
		common.ServerPort = resolvedPort
	}

	// 初始化当前地址（动态刷新时对比用）
	common.CurrentServerAddr = resolvedHost
	common.CurrentServerPort = resolvedPort

	common.Metas = GetMapWithoutPrefix(s.KeysHash(), "meta_")
	common.OidcAdditionalEndpointParams = GetMapWithoutPrefix(s.KeysHash(), "oidc_additional_")

	return common, nil
}

// 5. 修正：结构体中私有字段改为大写开头（导出字段，动态刷新时其他包可访问）
type ClientCommonConf struct {
	legacyauth.ClientConfig `ini:",extends"`

	// 原有客户端配置字段（保持不变）
	ServerAddr string `ini:"server_addr" json:"server_addr"`
	ServerPort int    `ini:"server_port" json:"server_port"`
	NatHoleSTUNServer string `ini:"nat_hole_stun_server" json:"nat_hole_stun_server"`
	DialServerTimeout int64 `ini:"dial_server_timeout" json:"dial_server_timeout"`
	DialServerKeepAlive int64 `ini:"dial_server_keepalive" json:"dial_server_keepalive"`
	ConnectServerLocalIP string `ini:"connect_server_local_ip" json:"connect_server_local_ip"`
	HTTPProxy string `ini:"http_proxy" json:"http_proxy"`
	LogFile string `ini:"log_file" json:"log_file"`
	LogWay string `ini:"log_way" json:"log_way"`
	LogLevel string `ini:"log_level" json:"log_level"`
	LogMaxDays int64 `ini:"log_max_days" json:"log_max_days"`
	DisableLogColor bool `ini:"disable_log_color" json:"disable_log_color"`
	AdminAddr string `ini:"admin_addr" json:"admin_addr"`
	AdminPort int `ini:"admin_port" json:"admin_port"`
	AdminUser string `ini:"admin_user" json:"admin_user"`
	AdminPwd string `ini:"admin_pwd" json:"admin_pwd"`
	AssetsDir string `ini:"assets_dir" json:"assets_dir"`
	PoolCount int `ini:"pool_count" json:"pool_count"`
	TCPMux bool `ini:"tcp_mux" json:"tcp_mux"`
	TCPMuxKeepaliveInterval int64 `ini:"tcp_mux_keepalive_interval" json:"tcp_mux_keepalive_interval"`
	User string `ini:"user" json:"user"`
	DNSServer string `ini:"dns_server" json:"dns_server"` // 客户端配置的DNS服务器
	LoginFailExit bool `ini:"login_fail_exit" json:"login_fail_exit"`
	Start []string `ini:"start" json:"start"`
	Protocol string `ini:"protocol" json:"protocol"`
	QUICKeepalivePeriod    int `ini:"quic_keepalive_period" json:"quic_keepalive_period"`
	QUICMaxIdleTimeout     int `ini:"quic_max_idle_timeout" json:"quic_max_idle_timeout"`
	QUICMaxIncomingStreams int `ini:"quic_max_incoming_streams" json:"quic_max_incoming_streams"`
	TLSEnable bool `ini:"tls_enable" json:"tls_enable"`
	TLSCertFile string `ini:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile string `ini:"tls_key_file" json:"tls_key_file"`
	TLSTrustedCaFile string `ini:"tls_trusted_ca_file" json:"tls_trusted_ca_file"`
	TLSServerName string `ini:"tls_server_name" json:"tls_server_name"`
	DisableCustomTLSFirstByte bool `ini:"disable_custom_tls_first_byte" json:"disable_custom_tls_first_byte"`
	HeartbeatInterval int64 `ini:"heartbeat_interval" json:"heartbeat_interval"`
	HeartbeatTimeout int64 `ini:"heartbeat_timeout" json:"heartbeat_timeout"`
	Metas map[string]string `ini:"-" json:"metas"`
	UDPPacketSize int64 `ini:"udp_packet_size" json:"udp_packet_size"`
	IncludeConfigFiles []string `ini:"includes" json:"includes"`
	PprofEnable bool `ini:"pprof_enable" json:"pprof_enable"`

	// 新增：TXT动态刷新相关字段（修正为大写开头，支持跨包访问）
	TXTRefreshInterval int64        `ini:"txt_refresh_interval" json:"txt_refresh_interval"` // 刷新间隔（秒）
	CurrentServerAddr  string       `ini:"-" json:"-"` // 修正：大写开头，导出字段
	CurrentServerPort  int          `ini:"-" json:"-"` // 修正：大写开头，导出字段
	Mu                 sync.RWMutex `ini:"-" json:"-"` // 修正：大写开头，导出锁
}

// 以下原有函数（LoadAllProxyConfsFromIni、renderRangeProxyTemplates等）保持不变
func LoadAllProxyConfsFromIni(
	prefix string,
	source any,
	start []string,
) (map[string]ProxyConf, map[string]VisitorConf, error) {
	f, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:         false,
		InsensitiveSections: false,
		InsensitiveKeys:     false,
		IgnoreInlineComment: true,
		AllowBooleanKeys:    true,
	}, source)
	if err != nil {
		return nil, nil, err
	}

	proxyConfs := make(map[string]ProxyConf)
	visitorConfs := make(map[string]VisitorConf)

	if prefix != "" {
		prefix += "."
	}

	startProxy := make(map[string]struct{})
	for _, s := range start {
		startProxy[s] = struct{}{}
	}

	startAll := len(startProxy) == 0

	rangeSections := make([]*ini.Section, 0)
	for _, section := range f.Sections() {
		if !strings.HasPrefix(section.Name(), "range:") {
			continue
		}
		rangeSections = append(rangeSections, section)
	}

	for _, section := range rangeSections {
		err = renderRangeProxyTemplates(f, section)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to render template for proxy %s: %v", section.Name(), err)
		}
	}

	for _, section := range f.Sections() {
		name := section.Name()

		if name == ini.DefaultSection || name == "common" || strings.HasPrefix(name, "range:") {
			continue
		}

		_, shouldStart := startProxy[name]
		if !startAll && !shouldStart {
			continue
		}

		roleType := section.Key("role").String()
		if roleType == "" {
			roleType = "server"
		}

		switch roleType {
		case "server":
			newConf, newErr := NewProxyConfFromIni(prefix, name, section)
			if newErr != nil {
				return nil, nil, fmt.Errorf("failed to parse proxy %s, err: %v", name, newErr)
			}
			proxyConfs[prefix+name] = newConf
		case "visitor":
			newConf, newErr := NewVisitorConfFromIni(prefix, name, section)
			if newErr != nil {
				return nil, nil, fmt.Errorf("failed to parse visitor %s, err: %v", name, newErr)
			}
			visitorConfs[prefix+name] = newConf
		default:
			return nil, nil, fmt.Errorf("proxy %s role should be 'server' or 'visitor'", name)
		}
	}
	return proxyConfs, visitorConfs, nil
}

func renderRangeProxyTemplates(f *ini.File, section *ini.Section) error {
	localPortStr := section.Key("local_port").String()
	remotePortStr := section.Key("remote_port").String()
	if localPortStr == "" || remotePortStr == "" {
		return fmt.Errorf("local_port or remote_port is empty")
	}

	localPorts, err := util.ParseRangeNumbers(localPortStr)
	if err != nil {
		return err
	}

	remotePorts, err := util.ParseRangeNumbers(remotePortStr)
	if err != nil {
		return err
	}

	if len(localPorts) != len(remotePorts) {
		return fmt.Errorf("local ports number should be same with remote ports number")
	}

	if len(localPorts) == 0 {
		return fmt.Errorf("local_port and remote_port is necessary")
	}

	prefix := strings.TrimSpace(strings.TrimPrefix(section.Name(), "range:"))

	for i := range localPorts {
		tmpname := fmt.Sprintf("%s_%d", prefix, i)

		tmpsection, err := f.NewSection(tmpname)
		if err != nil {
			return err
		}

		copySection(section, tmpsection)
		if _, err := tmpsection.NewKey("local_port", fmt.Sprintf("%d", localPorts[i])); err != nil {
			return fmt.Errorf("local_port new key error: %v", err)
		}
		if _, err := tmpsection.NewKey("remote_port", fmt.Sprintf("%d", remotePorts[i])); err != nil {
			return fmt.Errorf("remote_port new key error: %v", err)
		}
	}

	return nil
}

func copySection(source, target *ini.Section) {
	for key, value := range source.KeysHash() {
		_, _ = target.NewKey(key, value)
	}
}

func GetDefaultClientConf() ClientCommonConf {
	return ClientCommonConf{
		ClientConfig:              legacyauth.GetDefaultClientConf(),
		TCPMux:                    true,
		LoginFailExit:             true,
		Protocol:                  "tcp",
		Start:                     make([]string, 0),
		TLSEnable:                 true,
		DisableCustomTLSFirstByte: true,
		Metas:                     make(map[string]string),
		IncludeConfigFiles:        make([]string, 0),
		TXTRefreshInterval:        0, // 默认关闭动态刷新（需用户手动设置>0的值）
	}
}

func (cfg *ClientCommonConf) Validate() error {
	if cfg.HeartbeatTimeout > 0 && cfg.HeartbeatInterval > 0 {
		if cfg.HeartbeatTimeout < cfg.HeartbeatInterval {
			return fmt.Errorf("heartbeat_timeout < heartbeat_interval")
		}
	}

	if !cfg.TLSEnable {
		if cfg.TLSCertFile != "" {
			fmt.Println("WARNING: tls_cert_file is invalid when tls_enable=false")
		}
		if cfg.TLSKeyFile != "" {
			fmt.Println("WARNING: tls_key_file is invalid when tls_enable=false")
		}
		if cfg.TLSTrustedCaFile != "" {
			fmt.Println("WARNING: tls_trusted_ca_file is invalid when tls_enable=false")
		}
	}

	if !slices.Contains([]string{"tcp", "kcp", "quic", "websocket", "wss"}, cfg.Protocol) {
		return fmt.Errorf("invalid protocol: %s", cfg.Protocol)
	}

	for _, f := range cfg.IncludeConfigFiles {
		absDir, err := filepath.Abs(filepath.Dir(f))
		if err != nil {
			return fmt.Errorf("include file dir parse failed: %s, err: %v", f, err)
		}
		if _, err := os.Stat(absDir); os.IsNotExist(err) {
			return fmt.Errorf("include file dir not exist: %s", absDir)
		}
	}

	// 新增：验证TXT刷新间隔（必须≥0）
	if cfg.TXTRefreshInterval < 0 {
		return fmt.Errorf("txt_refresh_interval must be ≥ 0 (current: %d)", cfg.TXTRefreshInterval)
	}

	return nil
}
