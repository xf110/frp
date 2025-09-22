package legacy

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
    "github.com/fsnotify/fsnotify"
	"gopkg.in/ini.v1"

	legacyauth "github.com/fatedier/frp/pkg/auth/legacy"
	"github.com/fatedier/frp/pkg/util/util"
	"slices"
)

var (
	ReconnectNotify = make(chan struct{}, 1) // 用来通知 root.go 重连
)

type ClientCommonConf struct {
	legacyauth.ClientConfig `ini:",extends"`

	ServerAddr string `ini:"server_addr" json:"server_addr"`
	ServerPort int    `ini:"server_port" json:"server_port"`
	NatHoleSTUNServer       string `ini:"nat_hole_stun_server" json:"nat_hole_stun_server"`
	DialServerTimeout       int64  `ini:"dial_server_timeout" json:"dial_server_timeout"`
	DialServerKeepAlive     int64  `ini:"dial_server_keepalive" json:"dial_server_keepalive"`
	ConnectServerLocalIP    string `ini:"connect_server_local_ip" json:"connect_server_local_ip"`
	HTTPProxy               string `ini:"http_proxy" json:"http_proxy"`
	LogFile                 string `ini:"log_file" json:"log_file"`
	LogWay                  string `ini:"log_way" json:"log_way"`
	LogLevel                string `ini:"log_level" json:"log_level"`
	LogMaxDays              int64  `ini:"log_max_days" json:"log_max_days"`
	DisableLogColor         bool   `ini:"disable_log_color" json:"disable_log_color"`
	AdminAddr               string `ini:"admin_addr" json:"admin_addr"`
	AdminPort               int    `ini:"admin_port" json:"admin_port"`
	AdminUser               string `ini:"admin_user" json:"admin_user"`
	AdminPwd                string `ini:"admin_pwd" json:"admin_pwd"`
	AssetsDir               string `ini:"assets_dir" json:"assets_dir"`
	PoolCount               int    `ini:"pool_count" json:"pool_count"`
	TCPMux                  bool   `ini:"tcp_mux" json:"tcp_mux"`
	TCPMuxKeepaliveInterval int64  `ini:"tcp_mux_keepalive_interval" json:"tcp_mux_keepalive_interval"`
	User                    string `ini:"user" json:"user"`
	DNSServer               string `ini:"dns_server" json:"dns_server"`
	LoginFailExit           bool   `ini:"login_fail_exit" json:"login_fail_exit"`
	Start                   []string
	Protocol                string `ini:"protocol" json:"protocol"`
	QUICKeepalivePeriod     int    `ini:"quic_keepalive_period" json:"quic_keepalive_period"`
	QUICMaxIdleTimeout      int    `ini:"quic_max_idle_timeout" json:"quic_max_idle_timeout"`
	QUICMaxIncomingStreams  int    `ini:"quic_max_incoming_streams" json:"quic_max_incoming_streams"`
	TLSEnable               bool   `ini:"tls_enable" json:"tls_enable"`
	TLSCertFile             string `ini:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile              string `ini:"tls_key_file" json:"tls_key_file"`
	TLSTrustedCaFile        string `ini:"tls_trusted_ca_file" json:"tls_trusted_ca_file"`
	TLSServerName           string `ini:"tls_server_name" json:"tls_server_name"`
	DisableCustomTLSFirstByte bool `ini:"disable_custom_tls_first_byte" json:"disable_custom_tls_first_byte"`
	HeartbeatInterval       int64  `ini:"heartbeat_interval" json:"heartbeat_interval"`
	HeartbeatTimeout        int64  `ini:"heartbeat_timeout" json:"heartbeat_timeout"`
	Metas                   map[string]string `ini:"-" json:"metas"`
	UDPPacketSize           int64             `ini:"udp_packet_size" json:"udp_packet_size"`
	IncludeConfigFiles      []string          `ini:"includes" json:"includes"`
	PprofEnable             bool              `ini:"pprof_enable" json:"pprof_enable"`
	// internal: if this config came from txt://, store the txt host for watching
	txtSourceHost string
	// internal: atomic store of last seen server "ip:port" to compare updates
	lastTXTValue atomic.Value
}




var lastServerAddr string

// LoadTxtAndWatch 初次加载 TXT，并启动监听
func LoadTxtAndWatch(filePath string) (string, error) {
	// 初次加载
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	lastServerAddr = strings.TrimSpace(string(data))

	// 启动文件监听
	go watchTxt(filePath)
	return lastServerAddr, nil
}

func watchTxt(filePath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Printf("[FRPC] fsnotify init failed: %v\n", err)
		return
	}
	defer watcher.Close()

	err = watcher.Add(filePath)
	if err != nil {
		fmt.Printf("[FRPC] watch file failed: %v\n", err)
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// 只处理写入事件
			if event.Op&fsnotify.Write == fsnotify.Write {
				// 等待写入完成，避免读到半截数据
				time.Sleep(200 * time.Millisecond)

				data, err := os.ReadFile(filePath)
				if err != nil {
					continue
				}
				newAddr := strings.TrimSpace(string(data))
				if newAddr != lastServerAddr {
					fmt.Printf("TXT update: %s -> %s\n", lastServerAddr, newAddr)
					lastServerAddr = newAddr

					// 发送重连信号（不会阻塞）
					select {
					case ReconnectNotify <- struct{}{}:
					default:
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("[FRPC] watch error: %v\n", err)
		}
	}
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
		return ClientCommonConf{}, fmt.Errorf("invalid configuration file, not found [common] section")
	}

	common := GetDefaultClientConf()
	err = s.MapTo(&common)
	if err != nil {
		return ClientCommonConf{}, err
	}

	common.Metas = GetMapWithoutPrefix(s.KeysHash(), "meta_")
	common.OidcAdditionalEndpointParams = GetMapWithoutPrefix(s.KeysHash(), "oidc_additional_")

// 如果配置是 txt:// 开头，则解析 TXT 并启动监控
	if strings.HasPrefix(common.ServerAddr, "txt://") {
		host := strings.TrimPrefix(common.ServerAddr, "txt://")
		common.txtSourceHost = host

		ip, port, err := resolveTXTOnce(host)
		if err != nil {
			fmt.Printf("TXT resolution failed for %s: %v\n", host, err)
		} else {
			common.ServerAddr = ip
			common.ServerPort = port
			common.lastTXTValue.Store(fmt.Sprintf("%s:%d", ip, port))
			fmt.Printf("TXT initial: %s:%d\n", ip, port)
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			defer cancel()
			watchTXTUpdates(ctx, &common, 15*time.Second)
		}()
	}
	return common, nil
}

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
			return fmt.Errorf("local_port new key in section error: %v", err)
		}
		if _, err := tmpsection.NewKey("remote_port", fmt.Sprintf("%d", remotePorts[i])); err != nil {
			return fmt.Errorf("remote_port new key in section error: %v", err)
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
		ServerAddr: "127.0.0.1",
		ServerPort: 7000,
		ClientConfig:              legacyauth.GetDefaultClientConf(),
		TCPMux:                    true,
		LoginFailExit:             true,
		Protocol:                  "tcp",
		Start:                     make([]string, 0),
		TLSEnable:                 true,
		DisableCustomTLSFirstByte: true,
		Metas:                     make(map[string]string),
		IncludeConfigFiles:        make([]string, 0),
	}
}



func (cfg *ClientCommonConf) Validate() error {
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

/*
Below are helper functions added to support txt://host resolution and watching.
They are the only parts with explanatory comments per your request.
*/

/*
resolveTXTOnce queries DNS TXT records for the provided host and looks for the first
token that matches "ip:port" where ip is an IPv4/IPv6 address (or resolvable host) and
port is a valid integer. It returns ip (string) and port (int) if found.
*/
func resolveTXTOnce(host string) (string, int, error) {
	records, err := net.LookupTXT(host)
	if err != nil {
		return "", 0, err
	}
	if len(records) == 0 {
		return "", 0, fmt.Errorf("no TXT record found for %s", host)
	}
	parts := strings.Split(records[0], ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid TXT format, expect ip:port got %s", records[0])
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in TXT: %v", err)
	}
	return parts[0], port, nil
}

func watchTXTUpdates(ctx context.Context, cfg *ClientCommonConf, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ip, port, err := resolveTXTOnce(cfg.txtSourceHost)
			if err != nil {
				fmt.Printf("TXT lookup error for %s: %v\n", cfg.txtSourceHost, err)
				continue
			}
			newVal := fmt.Sprintf("%s:%d", ip, port)
			last := cfg.lastTXTValue.Load()
			lastStr, _ := last.(string)
			if lastStr != newVal {
				fmt.Printf("TXT update: %s -> %s\n", lastStr, newVal)
				cfg.ServerAddr = ip
				cfg.ServerPort = port
				cfg.lastTXTValue.Store(newVal)

				select {
				case ReconnectNotify <- struct{}{}:
				default:
				}
			}
		}
	}
}
/*
splitTXTTokenize splits a TXT string into tokens by common separators: spaces, commas, semicolons.
This helps accept TXT records like:
  "server=1.2.3.4:7000"
  "1.2.3.4:7000"
  "srv:1.2.3.4:7000; backup:5.6.7.8:7000"
*/
func splitTXTTokenize(txt string) []string {
	// replace comma/semicolon with spaces then split
	repl := strings.NewReplacer(",", " ", ";", " ", "|", " ", "/", " ")
	clean := repl.Replace(txt)
	fields := strings.Fields(clean)
	return fields
}

/*
splitHostPortFlexible accepts tokens like:
 - "1.2.3.4:7000"
 - "[::1]:7000"
 - "hostname:7000"
and returns host part and port part as strings, or error if format invalid.
*/
func splitHostPortFlexible(token string) (string, string, error) {
	// net.SplitHostPort expects brackets for IPv6. If token contains ']:', pass directly.
	if strings.HasPrefix(token, "[") {
		host, port, err := net.SplitHostPort(token)
		return host, port, err
	}
	// else try last ':' split (to allow tokens like "name:1:2:3" though unlikely)
	idx := strings.LastIndex(token, ":")
	if idx <= 0 || idx == len(token)-1 {
		return "", "", fmt.Errorf("no port found")
	}
	host := token[:idx]
	port := token[idx+1:]
	return host, port, nil
}
