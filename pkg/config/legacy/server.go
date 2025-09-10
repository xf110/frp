// client/service.go
package legacy

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"strings"

	"gopkg.in/ini.v1"

	legacyauth "github.com/fatedier/frp/pkg/auth/legacy"
)

// Service 管理frpc客户端的核心服务逻辑
type Service struct {
	cfg          *legacy.ClientCommonConf
	conn         net.Conn          // 当前与frps的连接
	proxyManager *ProxyManager     // 代理管理器
	runner       *Runner           // 客户端运行器
	mu           sync.Mutex        // 保护conn等字段的互斥锁
}

// NewService 创建一个新的客户端服务实例
func NewService(cfg *legacy.ClientCommonConf) (*Service, error) {
	proxyManager, err := NewProxyManager(cfg)
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:          cfg,
		proxyManager: proxyManager,
		runner:       NewRunner(cfg, proxyManager),
	}, nil
}

// Run 启动客户端服务
func (s *Service) Run() error {
	// 1. 初始化服务器地址（首次解析TXT记录）
	if err := s.initServerAddr(); err != nil {
		return fmt.Errorf("初始化服务器地址失败: %v", err)
	}

	// 2. 建立初始连接
	if err := s.connect(); err != nil {
		return fmt.Errorf("首次连接失败: %v", err)
	}

	// 3. 启动客户端核心运行逻辑
	if err := s.runner.Run(s.conn); err != nil {
		return fmt.Errorf("启动客户端运行器失败: %v", err)
	}

	// 4. 如果配置了TXT刷新间隔，启动定时刷新任务
	if s.cfg.TXTRefreshInterval > 0 {
		go s.startTXTRefreshTask()
		log.Infof("已启动TXT记录自动刷新，间隔为 %d 秒", s.cfg.TXTRefreshInterval)
	}

	return nil
}

// initServerAddr 初始化服务器地址（首次解析TXT记录）
func (s *Service) initServerAddr() error {
	s.cfg.Mu.Lock()
	defer s.cfg.Mu.Unlock()

	resolvedAddr, resolvedPort, err := legacy.ResolveServerAddr(s.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("解析TXT记录失败: %v", err)
	}

	// 保存首次解析的地址和端口
	s.cfg.CurrentServerAddr = resolvedAddr
	s.cfg.CurrentServerPort = resolvedPort
	log.Infof("首次解析服务器地址: %s:%d", resolvedAddr, resolvedPort)
	return nil
}

// startTXTRefreshTask 启动TXT记录定时刷新任务
func (s *Service) startTXTRefreshTask() {
	ticker := time.NewTicker(time.Duration(s.cfg.TXTRefreshInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Debugf("开始TXT记录刷新检查")
		if err := s.refreshTXTRecord(); err != nil {
			log.Warnf("TXT记录刷新失败: %v", err)
		}
	}
}

// refreshTXTRecord 刷新TXT记录并检查地址变化
func (s *Service) refreshTXTRecord() error {
	// 解析新地址
	newAddr, newPort, err := legacy.ResolveServerAddr(s.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("解析TXT记录失败: %v", err)
	}

	// 对比新旧地址
	s.cfg.Mu.RLock()
	oldAddr, oldPort := s.cfg.CurrentServerAddr, s.cfg.CurrentServerPort
	s.cfg.Mu.RUnlock()

	if newAddr == oldAddr && newPort == oldPort {
		log.Debugf("服务器地址未变化: %s:%d", newAddr, newPort)
		return nil
	}

	// 地址变化，尝试重连
	log.Infof("服务器地址已更新: 旧地址=%s:%d -> 新地址=%s:%d，尝试重连...",
		oldAddr, oldPort, newAddr, newPort)

	if err := s.reconnectWithNewAddr(newAddr, newPort); err != nil {
		return fmt.Errorf("重连新地址失败: %v", err)
	}

	// 重连成功，更新当前地址
	s.cfg.Mu.Lock()
	s.cfg.CurrentServerAddr = newAddr
	s.cfg.CurrentServerPort = newPort
	s.cfg.Mu.Unlock()

	log.Infof("重连新地址成功: %s:%d", newAddr, newPort)
	return nil
}

// reconnectWithNewAddr 使用新地址重连服务器
func (s *Service) reconnectWithNewAddr(newAddr string, newPort int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. 暂停代理服务
	s.proxyManager.Pause()
	defer s.proxyManager.Resume()

	// 2. 关闭旧连接
	if s.conn != nil {
		s.conn.Close()
		log.Debugf("已关闭旧连接")
	}

	// 3. 尝试建立新连接（带重试）
	var newConn net.Conn
	var err error
	for i := 0; i < 3; i++ { // 最多重试3次
		newConn, err = s.dialNewServer(newAddr, newPort)
		if err == nil {
			break
		}
		log.Warnf("第 %d 次连接新地址失败: %v，将重试", i+1, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		// 尝试恢复旧连接
		if err := s.recoverOldConnection(); err != nil {
			log.Errorf("恢复旧连接失败: %v", err)
		}
		return fmt.Errorf("多次尝试连接新地址失败: %v", err)
	}

	// 4. 使用新连接重新启动客户端
	if err := s.runner.Restart(newConn); err != nil {
		newConn.Close()
		return fmt.Errorf("新连接启动客户端失败: %v", err)
	}

	// 5. 更新连接
	s.conn = newConn
	return nil
}

// dialNewServer 连接新的服务器地址
func (s *Service) dialNewServer(addr string, port int) (net.Conn, error) {
	serverAddr := fmt.Sprintf("%s:%d", addr, port)
	log.Debugf("尝试连接新服务器: %s", serverAddr)

	// 使用客户端配置创建拨号器
	dialer := transport.NewDialer(
		transport.WithDialServerTimeout(time.Duration(s.cfg.DialServerTimeout)*time.Second),
		transport.WithProxy(s.cfg.HTTPProxy),
		transport.WithTLSConfig(s.cfg.TLSEnable, s.cfg.TLSCertFile, s.cfg.TLSKeyFile,
			s.cfg.TLSTrustedCaFile, s.cfg.TLSServerName, s.cfg.DisableCustomTLSFirstByte),
		transport.WithLocalIP(s.cfg.ConnectServerLocalIP),
	)

	conn, err := dialer.Dial(s.cfg.Protocol, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("拨号失败: %v", err)
	}
	return conn, nil
}

// recoverOldConnection 尝试恢复到旧连接
func (s *Service) recoverOldConnection() error {
	s.cfg.Mu.RLock()
	oldAddr, oldPort := s.cfg.CurrentServerAddr, s.cfg.CurrentServerPort
	s.cfg.Mu.RUnlock()

	log.Infof("尝试恢复到旧地址: %s:%d", oldAddr, oldPort)

	conn, err := s.dialNewServer(oldAddr, oldPort)
	if err != nil {
		return fmt.Errorf("连接旧地址失败: %v", err)
	}

	if err := s.runner.Restart(conn); err != nil {
		conn.Close()
		return fmt.Errorf("旧连接启动客户端失败: %v", err)
	}

	s.conn = conn
	return nil
}

// Close 关闭客户端服务
func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		s.conn.Close()
	}
	s.runner.Close()
	log.Info("客户端服务已关闭")
}
