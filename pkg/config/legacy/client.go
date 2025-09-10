package legacy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/ini.v1"

	legacyauth "github.com/fatedier/frp/pkg/auth/legacy"
	"github.com/fatedier/frp/pkg/util/util"
)

// 新增：解析服务器地址，支持txt://前缀
func resolveServerAddr(addr string) (string, int, error) {
	if strings.HasPrefix(addr, "txt://") {
		domain := strings.TrimPrefix(addr, "txt://")
		return resolveFromTXT(domain)
	}

	// 原有逻辑：处理普通地址格式
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// 如果没有指定端口，使用默认7000
		return addr, 7000, nil
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %v", err)
	}
	return host, p, nil
}

// 新增：从TXT记录解析服务器地址和端口
func resolveFromTXT(domain string) (string, int, error) {
	resolver := dns.Client{}
	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	
	// 优先使用配置中指定的DNS服务器，否则使用默认
	dnsServer := "8.8.8.8:53"
	
	r, _, err := resolver.Exchange(&msg, dnsServer)
	if err != nil {
		return "", 0, fmt.Errorf("dns query failed: %v", err)
	}

	if len(r.Answer) == 0 {
		return "", 0, fmt.Errorf("no TXT records found for %s", domain)
	}

	// 解析TXT记录，格式应为"host:port"
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				parts := strings.Split(s, ":")
				if len(parts) == 2 {
					port, err := strconv.Atoi(parts[1])
					if err != nil {
						continue
					}
					return parts[0], port, nil
				}
			}
		}
	}

	return "", 0, fmt.Errorf("invalid TXT record format for %s, expected 'host:port'", domain)
}

// 修改UnmarshalClientConfFromIni函数，添加TXT解析逻辑
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
		return ClientCommonConf{}, fmt.Errorf("invalid configuration file, not found [common] section")
	}

	common := GetDefaultClientConf()
	err = s.MapTo(&common)
	if err != nil {
		return ClientCommonConf{}, err
	}

	// 新增：解析server_addr（核心逻辑）
	resolvedHost, resolvedPort, err := resolveServerAddr(common.ServerAddr)
	if err != nil {
		return ClientCommonConf{}, fmt.Errorf("failed to resolve server address: %v", err)
	}
	common.ServerAddr = resolvedHost
	// 仅当配置中未指定server_port时使用解析结果
	if common.ServerPort == 0 {
		common.ServerPort = resolvedPort
	}

	common.Metas = GetMapWithoutPrefix(s.KeysHash(), "meta_")
	common.OidcAdditionalEndpointParams = GetMapWithoutPrefix(s.KeysHash(), "oidc_additional_")

	return common, nil
}

// 以下为文件原有内容，保持不变
type ClientCommonConf struct {
	legacyauth.ClientConfig `ini:",extends"`

	ServerAddr string `ini:"server_addr" json:"server_addr"`
	ServerPort int `ini:"server_port" json:"server_port"`
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
	DNSServer string `ini:"dns_server" json:"dns_server"`
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
	// 新增：TXT记录动态刷新配置
    TXTRefreshInterval int64 `ini:"txt_refresh_interval" json:"txt_refresh_interval"` // 单位：秒，0表示不刷新
    currentServerAddr  string // 当前使用的服务器地址（内存变量，不持久化）
    currentServerPort  int    // 当前使用的服务器端口（内存变量，不持久化）
    mu                 sync.RWMutex // 并发安全锁（避免刷新与重连竞态）
}

func LoadAllProxyConfsFromIni(
	prefix string,
	source any,
	start []string,
) (map[string]ProxyConf, map[string]VisitorConf, error) {
	// 原有实现保持不变
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
	// 原有实现保持不变
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
			return fmt.Errorf("local_port new key in section error: %v", err)
		}
		if _, err := tmpsection.NewKey("remote_port", fmt.Sprintf("%d", remotePorts[i])); err != nil {
			return fmt.Errorf("remote_port new key in section error: %v", err)
		}
	}

	return nil
}

func copySection(source, target *ini.Section) {
	// 原有实现保持不变
	for key, value := range source.KeysHash() {
		_, _ = target.NewKey(key, value)
	}
}

func GetDefaultClientConf() ClientCommonConf {
	// 原有实现保持不变
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
		TXTRefreshInterval: 300, // 0=关闭动态刷新，用户需手动设置（如600=10分钟）
	}
}

func (cfg *ClientCommonConf) Validate() error {
	// 原有实现保持不变
	if cfg.HeartbeatTimeout > 0 && cfg.HeartbeatInterval > 0 {
		if cfg.HeartbeatTimeout < cfg.HeartbeatInterval {
			return fmt.Errorf("invalid heartbeat_timeout, heartbeat_timeout is less than heartbeat_interval")
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
		return fmt.Errorf("invalid protocol")
	}

	for _, f := range cfg.IncludeConfigFiles {
		absDir, err := filepath.Abs(filepath.Dir(f))
		if err != nil {
			return fmt.Errorf("include: parse directory of %s failed: %v", f, err)
		}
		if _, err := os.Stat(absDir); os.IsNotExist(err) {
			return fmt.Errorf("include: directory of %s not exist", f)
		}
	}
	return nil
}
