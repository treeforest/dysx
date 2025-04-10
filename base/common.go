package base

import "C"

const (
	// DefaultPIN 默认PIN码（口令）
	DefaultPIN = "11111111"
)

// ECCKeyType ECC 密钥对类型
type ECCKeyType uint

const (
	// ECCKeyTypeEncrypt 加密密钥对
	ECCKeyTypeEncrypt ECCKeyType = 0
	// ECCKeyTypeSign 签名密钥对
	ECCKeyTypeSign ECCKeyType = 1
)

// VCtrlType 控制类型
type VCtrlType int

const (
	V_CTL_UMG_INIT_EXUK VCtrlType = 0x104
)
