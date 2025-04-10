package dysx

import (
	"github.com/pingcap/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/treeforest/dysx/base"
)

func getAdminPin(adminPins ...string) string {
	if len(adminPins) > 0 {
		return adminPins[0]
	}
	return base.DefaultPIN
}

func (h *SDFHandle) InitDevice() error {
	return h.withSession(func(device base.DeviceHandle, session base.SessionHandle) error {
		err := h.ctx.PCIVControl(device, base.V_CTL_UMG_INIT_EXUK)
		if err != nil {
			return errors.WithStack(err)
		}

		err = h.ctx.SDFMInitKeyFileSystem(session, base.DefaultPIN, base.DefaultPIN, base.DefaultPIN)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
}

// ImportECCKeyPair 导入ECC密钥对（签名和加密密钥）
func (h *SDFHandle) ImportECCKeyPair(keyIndex uint32, privateKey *sm2.PrivateKey, adminPins ...string) error {
	return h.withSession(func(device base.DeviceHandle, session base.SessionHandle) error {
		adminPin := getAdminPin(adminPins...)
		return h.importECCKeyPair(session, keyIndex, privateKey, adminPin)
	})
}

func (h *SDFHandle) importECCKeyPair(session base.SessionHandle, keyIndex uint32, privateKey *sm2.PrivateKey, adminPin string) error {
	err := h.ctx.SDFGetPrivateKeyAccessRight(session, uint(keyIndex), adminPin)
	if err != nil {
		return errors.WithStack(err)
	}

	err = h.ctx.SDFEImportKeyPairECC(session, base.ECCKeyTypeSign, uint(keyIndex), privateKey)
	if err != nil {
		return errors.WithStack(err)
	}

	err = h.ctx.SDFEImportKeyPairECC(session, base.ECCKeyTypeEncrypt, uint(keyIndex), privateKey)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (h *SDFHandle) deleteECCKeyPair(session base.SessionHandle, keyIndex uint32, adminPin string) error {
	err := h.ctx.SDFMDeleteInternalKeyPairECC(session, base.ECCKeyTypeSign, uint(keyIndex), adminPin)
	if err != nil {
		return errors.WithStack(err)
	}
	err = h.ctx.SDFMDeleteInternalKeyPairECC(session, base.ECCKeyTypeEncrypt, uint(keyIndex), adminPin)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// ImportECCKeyPairForce 强制导入ECC密钥对（签名和加密密钥）
func (h *SDFHandle) ImportECCKeyPairForce(keyIndex uint32, privateKey *sm2.PrivateKey, adminPins ...string) error {
	return h.withSession(func(device base.DeviceHandle, session base.SessionHandle) error {
		adminPin := getAdminPin(adminPins...)

		// 先删除密钥，避免已存在密钥的情况下导入失败
		err := h.deleteECCKeyPair(session, keyIndex, adminPin)
		if err != nil {
			return errors.WithStack(err)
		}

		err = h.importECCKeyPair(session, keyIndex, privateKey, adminPin)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
}

// BatchImportECCKeyPairs 批量导入所有 ECC 密钥对
func (h *SDFHandle) BatchImportECCKeyPairs(sm2KeyPairCollectionData []byte) error {
	collection := NewSM2KeyPairCollection()
	err := collection.Deserialize(sm2KeyPairCollectionData)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, pair := range collection.Pairs {
		err = h.ImportECCKeyPairForce(pair.Index, pair.Key)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
