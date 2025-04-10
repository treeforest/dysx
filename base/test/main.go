package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/treeforest/dysx/base"
	"log/slog"
)

func main() {
	libPath := flag.String("lib", "./libsdf.so", "library path")
	flag.Parse()

	slog.SetLogLoggerLevel(slog.LevelDebug)

	ctx := base.New(*libPath)
	if ctx == nil {
		panic("failed to load library")
	}
	defer ctx.Destroy()

	slog.Info("SDFOpenDevice")
	deviceHandle, err := ctx.SDFOpenDevice()
	if err != nil {
		panic(err)
	}

	defer func() {
		slog.Info("SDFCloseDevice")
		err = ctx.SDFCloseDevice(deviceHandle)
		if err != nil {
			panic(err)
		}
	}()

	slog.Info("SDFOpenSession")
	sessionHandle, err := ctx.SDFOpenSession(deviceHandle)
	if err != nil {
		panic(err)
	}

	defer func() {
		slog.Info("SDFCloseSession")
		err = ctx.SDFCloseSession(sessionHandle)
		if err != nil {
			panic(err)
		}
	}()

	// initDevice(ctx, deviceHandle, sessionHandle)
	importKeyPairECC(ctx, sessionHandle)
}

func initDevice(ctx *base.Ctx, deviceHandle base.DeviceHandle, sessionHandle base.SessionHandle) {
	slog.Info("初始化设备")
	if err := ctx.PCIVControl(deviceHandle, base.V_CTL_UMG_INIT_EXUK); err != nil {
		panic(err)
	}
	err := ctx.SDFMInitKeyFileSystem(sessionHandle, base.DefaultPIN, base.DefaultPIN, base.DefaultPIN)
	if err != nil {
		panic(err)
	}
}

func importKeyPairECC(ctx *base.Ctx, sessionHandle base.SessionHandle) {
	slog.Info("导入 ECC 密钥")
	err := ctx.SDFGetPrivateKeyAccessRight(sessionHandle, 1, base.DefaultPIN)
	if err != nil {
		panic(err)
	}

	key, _ := sm2.GenerateKey(rand.Reader)
	fmt.Println("bits: ", key.Curve.Params().BitSize)
	fmt.Println("D: ", key.D.Bytes())
	fmt.Println("X: ", key.PublicKey.X.Bytes())
	fmt.Println("Y: ", key.PublicKey.Y.Bytes())

	// 删除签名密钥
	if err = ctx.SDFMDeleteInternalKeyPairECC(sessionHandle, base.ECCKeyTypeSign, 1, base.DefaultPIN); err != nil {
		panic(err)
	}

	// 导入签名密钥
	if err = ctx.SDFEImportKeyPairECC(sessionHandle, base.ECCKeyTypeSign, 1, key); err != nil {
		panic(err)
	}

	// 删除加密密钥
	if err = ctx.SDFMDeleteInternalKeyPairECC(sessionHandle, base.ECCKeyTypeEncrypt, 1, base.DefaultPIN); err != nil {
		panic(err)
	}

	// 导入加密密钥
	if err = ctx.SDFEImportKeyPairECC(sessionHandle, base.ECCKeyTypeEncrypt, 1, key); err != nil {
		panic(err)
	}
}
