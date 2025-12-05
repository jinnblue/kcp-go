//go:build !debug

// if build tag debug is not set, then debugLog will ingore in compile time
package kcp

func (kcp *KCP) debugLog(logtype KCPLogType, args ...any) {}

func (l *Listener) debugLog(logtype ListenLogType, args ...any) {}
