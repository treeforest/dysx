package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/treeforest/dysx"
	"log/slog"
	"os"
)

var sdfHandle *dysx.SDFHandle

func exampleInitDevice() {
	slog.Info(">> 设备初始化")
	err := sdfHandle.InitDevice()
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
	}
}

func exampleImportECCKeyPair(keyIndex uint32) {
	key, _ := sm2.GenerateKey(rand.Reader)
	fmt.Println("D: ", key.D.Bytes())
	fmt.Println("X: ", key.PublicKey.X.Bytes())
	fmt.Println("Y: ", key.PublicKey.Y.Bytes())

	slog.Info(fmt.Sprintf(">> 导入ECC密钥 | 索引:%d", keyIndex))
	err := sdfHandle.ImportECCKeyPairForce(keyIndex, key)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
	}
}

func exampleBatchImportECCKeyPairs(count int) {
	slog.Info(">> 批量导入ECC密钥")

	collection := dysx.NewSM2KeyPairCollection()
	for i := 1; i <= count; i++ {
		key, _ := sm2.GenerateKey(rand.Reader)
		collection.Pairs = append(collection.Pairs, dysx.NewSM2KeyPair(uint32(i), key))
	}

	collectionData, err := collection.Serialize()
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(-1)
	}

	err = sdfHandle.BatchImportECCKeyPairs(collectionData)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(-1)
	}
}

func main() {
	libPath := flag.String("lib", "./libsdf.so", "path to library")
	initDevice := flag.Bool("initDevice", false, "init device")
	importECCKeyPair := flag.Bool("importECCKeyPair", false, "import ECC key pair")
	batchImportECCKeyPairs := flag.Bool("batchImportECCKeyPairs", false, "batch import ECC key pairs")
	keyIndex := flag.Uint("keyIndex", 1, "key index")
	keyCount := flag.Int("keyCount", 1, "key count")
	flag.Parse()

	var err error
	sdfHandle, err = dysx.New(*libPath, 10)
	if err != nil {
		panic(err)
	}
	defer sdfHandle.Close()

	switch {
	case *initDevice:
		exampleInitDevice()
	case *importECCKeyPair:
		exampleImportECCKeyPair(uint32(*keyIndex))
	case *batchImportECCKeyPairs:
		exampleBatchImportECCKeyPairs(*keyCount)
	}
}
