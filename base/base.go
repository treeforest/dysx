package base

/*
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include <dlfcn.h>
#include <sdf.h>

struct LibHandle {
	void *handle;
};

struct LibHandle *DYSXNewLib(const char *iLibrary)
{
	struct LibHandle *h = calloc(1,sizeof(struct LibHandle));
	h->handle = dlopen(iLibrary,1);
	if(h->handle == NULL){
		free(h);
		return NULL;
	}
	return h;
}

void DYSXDestroyLib(struct LibHandle *h)
{
	if (!h) {
		return;
	}
	if (h->handle == NULL) {
		return;
	}
	if (dlclose(h->handle) < 0) {
		return;
	}
	free(h);
}

// *** 设备管理类函数 ***
// 打开设备
int DYSXSDFOpenDevice(struct LibHandle * h, void **phDeviceHandle)
{
    typedef int (*FPTR)(void**);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_OpenDevice");
	return (*fptr)(phDeviceHandle);
}
// 关闭设备
int DYSXSDFCloseDevice(struct LibHandle * h,void *hDeviceHandle)
{
    typedef int (*FPTR)(void*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CloseDevice");
	return (*fptr)(hDeviceHandle);
}
// 创建会话
int DYSXSDFOpenSession(struct LibHandle * h,void *hDeviceHandle, void **phSessionHandle)
{
    typedef int (*FPTR)(void*,void**);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_OpenSession");
	return (*fptr)(hDeviceHandle,phSessionHandle);
}
// 关闭会话
int DYSXSDFCloseSession(struct LibHandle * h,void* hSessionHandle)
{
    typedef int (*FPTR)(void*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CloseSession");
	return (*fptr)(hSessionHandle);
}

// *** 密码卡管理函数 ***

// PCI初始化
int DYSXPCIVControl(struct LibHandle * h, void *hDeviceHandle, int request)
{
	typedef int (*FPTR)(void*, int, ...);
	FPTR fptr = (FPTR)dlsym(h->handle, "PCI_V_Control");
	return (*fptr)(hDeviceHandle, V_CTL_UMG_INIT_EXUK);
}

// 初始化密钥文件系统
int DYSXSDFMInitKeyFileSystem(struct LibHandle * h, void *hSessionHandle, char *AdminPin, char *NewAdminPin, char *NewUserPIN)
{
	unsigned char root_key[16] = {0xAF,0x86,0x18,0x23,0x8C,0x94,0xA1,0x19,0xAE,0x6D,0xE9,0x22,0xDB,0xB9,0x35,0x4D};

	typedef int (*FPTR)(void*, char*, unsigned char*, unsigned int, char*, char*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDFM_InitKeyFileSystem");
	return (*fptr)(hSessionHandle, AdminPin, root_key, 128, NewAdminPin, NewUserPIN);
}

// 获取 ECC 密钥对访问权限
int DYSXSDFGetPrivateKeyAccessRight(struct LibHandle * h, void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength)
{
	// int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength);
	typedef int (*FPTR)(void*, unsigned int, unsigned char*, unsigned int);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GetPrivateKeyAccessRight");
	return (*fptr)(hSessionHandle, uiKeyIndex, pucPassword, uiPwdLength);
}

// 导入 ECC 密钥对
int DYSXSDFEImportKeyPairECC(struct LibHandle * h, void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex,  ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
	// int SDFE_ImportKeyPair_ECC(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex,  ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
	typedef int (*FPTR)(void*, unsigned int, unsigned int, ECCrefPublicKey*, ECCrefPrivateKey*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDFE_ImportKeyPair_ECC");
	return (*fptr)(hSessionHandle, uiSignFlag, uiKeyIndex, pucPublicKey, pucPrivateKey);
}

// 删除 ECC 密钥对
int DYSXSDFMDeleteInternalKeyPairECC(struct LibHandle * h, void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, char *AdminPIN)
{
	// int SDFM_DeleteInternalKeyPair_ECC (void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, char *AdminPIN);
	typedef int (*FPTR)(void*, unsigned int, unsigned int, char*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDFM_DeleteInternalKeyPair_ECC");
	return (*fptr)(hSessionHandle, uiSignFlag, uiKeyIndex, AdminPIN);
}

*/
import "C"
import (
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/tjfoc/gmsm/sm2"
)

func ToError(e C.int) error {
	if e == 0 {
		return nil
	}
	return fmt.Errorf("sdf error: 0x%X", uint(e))
}

type Ctx struct {
	libHandle *C.struct_LibHandle
}

type DeviceHandle *C.void
type SessionHandle *C.void

func New(libPath string) *Ctx {
	c := new(Ctx)
	mod := C.CString(libPath)
	defer C.free(unsafe.Pointer(mod))
	c.libHandle = C.DYSXNewLib(mod)
	if c.libHandle == nil {
		slog.Error("failed to load library", slog.Any("errMsg", C.GoString(C.dlerror())))
		return nil
	}
	return c
}

func (c *Ctx) Destroy() {
	if c.libHandle != nil {
		C.DYSXDestroyLib(c.libHandle)
	}
}

// SDFOpenDevice 打开设备
func (c *Ctx) SDFOpenDevice() (DeviceHandle, error) {
	slog.Debug("SDF_OpenDevice")
	var device unsafe.Pointer
	rv := C.DYSXSDFOpenDevice(c.libHandle, &device)
	return DeviceHandle(device), ToError(rv)
}

// SDFCloseDevice 关闭设备
func (c *Ctx) SDFCloseDevice(deviceHandle DeviceHandle) (err error) {
	slog.Debug("SDF_CloseDevice")
	rv := C.DYSXSDFCloseDevice(c.libHandle, unsafe.Pointer(deviceHandle))
	return ToError(rv)
}

// SDFOpenSession 创建会话
func (c *Ctx) SDFOpenSession(deviceHandle DeviceHandle) (SessionHandle, error) {
	slog.Debug("SDF_OpenSession")
	var session unsafe.Pointer
	rv := C.DYSXSDFOpenSession(
		c.libHandle,
		unsafe.Pointer(deviceHandle),
		&session,
	)
	return SessionHandle(session), ToError(rv)
}

// SDFCloseSession 关闭会话
func (c *Ctx) SDFCloseSession(sessionHandle SessionHandle) error {
	slog.Debug("SDF_CloseSession")
	rv := C.DYSXSDFCloseSession(c.libHandle, unsafe.Pointer(sessionHandle))
	return ToError(rv)
}

// PCIVControl PCI V 控制
func (c *Ctx) PCIVControl(deviceHandle DeviceHandle, vCtrl VCtrlType) error {
	slog.Debug("PCI_V_Control")
	rv := C.DYSXPCIVControl(c.libHandle, unsafe.Pointer(deviceHandle), C.int(vCtrl))
	return ToError(rv)
}

// SDFMInitKeyFileSystem 初始化密钥文件系统
func (c *Ctx) SDFMInitKeyFileSystem(
	sessionHandle SessionHandle,
	oldAdminPin string,
	newAdminPin string,
	newUserPin string,
) error {
	slog.Debug("SDFM_InitKeyFileSystem")

	var (
		cOldAdminPin *C.char
		cNewAdminPin *C.char
		cNewUserPin  *C.char
	)

	if oldAdminPin == "" {
		oldAdminPin = DefaultPIN
	}
	if newAdminPin == "" {
		newAdminPin = DefaultPIN
	}
	if newUserPin == "" {
		newUserPin = DefaultPIN
	}

	cOldAdminPin = C.CString(oldAdminPin)
	defer C.free(unsafe.Pointer(cOldAdminPin))

	cNewAdminPin = C.CString(newAdminPin)
	defer C.free(unsafe.Pointer(cNewAdminPin))

	cNewUserPin = C.CString(newUserPin)
	defer C.free(unsafe.Pointer(cNewUserPin))

	rv := C.DYSXSDFMInitKeyFileSystem(
		c.libHandle,
		unsafe.Pointer(sessionHandle),
		cOldAdminPin,
		cNewAdminPin,
		cNewUserPin,
	)
	return ToError(rv)
}

// SDFGetPrivateKeyAccessRight 获取 ECC 密钥对访问权限
func (c *Ctx) SDFGetPrivateKeyAccessRight(sessionHandle SessionHandle, keyIndex uint, password string) error {
	slog.Debug("SDF_GetPrivateKeyAccessRight")

	if password == "" {
		password = DefaultPIN
	}
	if keyIndex == 0 {
		keyIndex = 1
	}

	// 类型安全转换：Go string → C unsigned char*
	cPassword := (*C.uchar)(unsafe.Pointer(C.CString(password)))
	defer func() {
		// 安全擦除内存（避免明文残留）
		//C.memset(unsafe.Pointer(cPassword), 0, C.size_t(len(password)))
		C.free(unsafe.Pointer(cPassword))
	}()

	rv := C.DYSXSDFGetPrivateKeyAccessRight(c.libHandle, unsafe.Pointer(sessionHandle), C.uint(keyIndex), cPassword, C.uint(len(password)))
	return ToError(rv)
}

// SDFEImportKeyPairECC 导入ECC密钥对
func (c *Ctx) SDFEImportKeyPairECC(sessionHandle SessionHandle, keyType ECCKeyType, keyIndex uint, privateKey *sm2.PrivateKey) error {
	slog.Debug("SDFE_ImportKeyPair_ECC")

	if keyIndex == 0 {
		// 默认索引为 1
		keyIndex = 1
	}

	privKey := convertToECCrefPrivateKeyC(privateKey)
	pubKey := convertToECCrefPublicKeyC(&privateKey.PublicKey)

	rv := C.DYSXSDFEImportKeyPairECC(c.libHandle, unsafe.Pointer(sessionHandle), C.uint(keyType), C.uint(keyIndex), &pubKey, &privKey)
	return ToError(rv)
}

func convertToECCrefPrivateKeyC(privateKey *sm2.PrivateKey) (pucPrivateKey C.ECCrefPrivateKey) {
	bits := privateKey.Curve.Params().BitSize // 若是 256，则 startIndex 为 32
	startIndex := 64 - bits/8
	slog.Debug("convertToECCrefPrivateKeyC", slog.Any("startIndex", startIndex))

	pucPrivateKey.bits = C.uint(bits)
	dBytes := privateKey.D.Bytes()
	for i := 0; i < len(dBytes); i++ {
		pucPrivateKey.K[startIndex+i] = C.uchar(dBytes[i])
	}
	return pucPrivateKey
}

func convertToECCrefPublicKeyC(publicKey *sm2.PublicKey) (pucPublicKey C.ECCrefPublicKey) {
	bits := publicKey.Curve.Params().BitSize // 若是 256，则 startIndex 为 32
	startIndex := 64 - bits/8
	slog.Debug("convertToECCrefPublicKeyC", slog.Any("startIndex", startIndex))

	pucPublicKey.bits = C.uint(bits)
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	for i := 0; i < len(xBytes); i++ {
		pucPublicKey.x[startIndex+i] = C.uchar(xBytes[i])
	}
	for i := 0; i < len(yBytes); i++ {
		pucPublicKey.y[startIndex+i] = C.uchar(yBytes[i])
	}
	return pucPublicKey
}

// SDFMDeleteInternalKeyPairECC 删除 ECC 密钥对
func (c *Ctx) SDFMDeleteInternalKeyPairECC(sessionHandle SessionHandle, keyType ECCKeyType, keyIndex uint, adminPin string) error {
	slog.Debug("SDFM_DeleteInternalKeyPair_ECC")

	if keyIndex == 0 {
		// 默认索引为 1
		keyIndex = 1
	}

	cAdminPin := C.CString(adminPin)
	defer C.free(unsafe.Pointer(cAdminPin))

	rv := C.DYSXSDFMDeleteInternalKeyPairECC(c.libHandle, unsafe.Pointer(sessionHandle), C.uint(keyType), C.uint(keyIndex), cAdminPin)
	if rv == C.SDR_KEYNOTEXIST {
		// 密钥不存在
		return nil
	}

	return ToError(rv)
}
