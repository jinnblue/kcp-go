//go:build debug

// only build tag debug is set, then debugLog will be enabled in compile time
package kcp

func (kcp *KCP) debugLog(logtype KCPLogType, args ...any) {
	if kcp.logmask&logtype == 0 {
		return
	}

	var msg string
	switch logtype {
	case IKCP_LOG_OUTPUT:
		msg = "[KCP OUTPUT]"
	case IKCP_LOG_INPUT:
		msg = "[KCP INPUT]"
	case IKCP_LOG_SEND:
		msg = "[KCP SEND]"
	case IKCP_LOG_RECV:
		msg = "[KCP RECV]"
	case IKCP_LOG_OUT_ACK:
		msg = "[KCP OUTPUT ACK]"
	case IKCP_LOG_OUT_PUSH:
		msg = "[KCP OUTPUT PUSH]"
	case IKCP_LOG_OUT_WASK:
		msg = "[KCP OUTPUT WASK]"
	case IKCP_LOG_OUT_WINS:
		msg = "[KCP OUTPUT WINS]"
	case IKCP_LOG_IN_ACK:
		msg = "[KCP INPUT ACK]"
	case IKCP_LOG_IN_PUSH:
		msg = "[KCP INPUT PUSH]"
	case IKCP_LOG_IN_WASK:
		msg = "[KCP INPUT WASK]"
	case IKCP_LOG_IN_WINS:
		msg = "[KCP INPUT WINS]"
	case IKCP_LOG_READ:
		msg = "[KCP READ]"
	case IKCP_LOG_WRITE:
		msg = "[KCP WRITE]"
	case IKCP_LOG_DEADLINK:
		msg = "[KCP DEADLINK]"
	}
	kcp.log(msg, args...)
}

func (l *Listener) debugLog(logtype ListenLogType, args ...any) {
	if l.logmask&logtype == 0 {
		return
	}

	var msg string
	switch logtype {
	case LISTEN_LOG_RDP_INPUT:
		msg = "[KCP LISTEN RDP INPUT]"
	case LISTEN_LOG_UDP_INPUT:
		msg = "[KCP LISTEN UDP INPUT]"
	case LISTEN_LOG_RDP_ORIGN:
		msg = "[KCP LISTEN RDP ORIGN]"
	case LISTEN_LOG_RDP_HELLO:
		msg = "[KCP LISTEN RDP HELLO]"
	case LISTEN_LOG_RDP_PING:
		msg = "[KCP LISTEN RDP PING]"
	case LISTEN_LOG_RDP_DATA:
		msg = "[KCP LISTEN RDP DATA]"
	case LISTEN_LOG_UDP_DATA:
		msg = "[KCP LISTEN UDP DATA]"
	case LISTEN_LOG_UDP_DISCONNECT:
		msg = "[KCP LISTEN UDP DISCONNECT]"
	case LISTEN_LOG_RDP_DROP:
		msg = "[KCP LISTEN RDP DROP]"
	case LISTEN_LOG_UDP_DROP:
		msg = "[KCP LISTEN UDP DROP]"
	}

	l.log(msg, args...)
}
