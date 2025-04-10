package dysx

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	tjsm2 "github.com/tjfoc/gmsm/sm2"
)

func generateTestKeyPair(t *testing.T) *tjsm2.PrivateKey {
	privKey, err := tjsm2.GenerateKey(rand.Reader)
	require.NoError(t, err, "生成测试密钥失败")
	return privKey
}

func TestSM2KeyPairCollection_SerializeDeserialize(t *testing.T) {
	// 测试用例数据准备
	validKeyPair := SM2KeyPair{
		Index: 1,
		Key:   generateTestKeyPair(t),
	}

	testCases := []struct {
		name          string
		input         SM2KeyPairCollection
		expectError   bool
		expectedIndex uint32
	}{
		{
			name: "单密钥正常序列化",
			input: SM2KeyPairCollection{
				Pairs: []SM2KeyPair{validKeyPair},
			},
			expectedIndex: 1,
		},
		{
			name: "多密钥正常序列化",
			input: SM2KeyPairCollection{
				Pairs: []SM2KeyPair{
					{Index: 1, Key: generateTestKeyPair(t)},
					{Index: 2, Key: generateTestKeyPair(t)},
				},
			},
			expectedIndex: 2,
		},
		{
			name: "空私钥处理",
			input: SM2KeyPairCollection{
				Pairs: []SM2KeyPair{
					{Index: 1, Key: nil},
				},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 序列化测试
			data, err := tc.input.Serialize()
			if tc.expectError {
				require.Error(t, err)
				return
			}
			//t.Logf("serialized: %s", data)
			require.NoError(t, err)

			// 反序列化测试
			var output SM2KeyPairCollection
			err = output.Deserialize(data)
			require.NoError(t, err)

			// 数据一致性验证
			require.Equal(t, len(tc.input.Pairs), len(output.Pairs))
			for i, pair := range output.Pairs {
				original := tc.input.Pairs[i]

				// 验证索引
				require.Equal(t, original.Index, pair.Index, "Index 不匹配")

				// 验证私钥参数
				if original.Key != nil {
					require.Equal(t,
						original.Key.D.Bytes(),
						pair.Key.D.Bytes(),
						"私钥D值不一致")

					// 验证公钥坐标
					require.Equal(t,
						original.Key.X.Bytes(),
						pair.Key.X.Bytes(),
						"X坐标不一致")
					require.Equal(t,
						original.Key.Y.Bytes(),
						pair.Key.Y.Bytes(),
						"Y坐标不一致")
				}
			}
		})
	}
}

func TestDeserializeEdgeCases(t *testing.T) {
	testCases := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "空输入数据",
			data:        []byte{},
			expectError: true,
		},
		{
			name:        "随机无效数据",
			data:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expectError: true,
		},
		{
			name:        "损坏的DER数据",
			data:        corruptDERData(generateValidTestData(t)),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var col SM2KeyPairCollection
			err := col.Deserialize(tc.data)
			require.Equal(t, tc.expectError, err != nil)
		})
	}
}

// 辅助函数 - 生成有效测试数据
func generateValidTestData(t *testing.T) []byte {
	col := SM2KeyPairCollection{
		Pairs: []SM2KeyPair{
			{
				Index: 1,
				Key:   generateTestKeyPair(t),
			},
		},
	}
	data, err := col.Serialize()
	require.NoError(t, err)
	return data
}

// 辅助函数 - 破坏DER数据结构
func corruptDERData(orig []byte) []byte {
	if len(orig) > 10 {
		corrupted := make([]byte, len(orig))
		copy(corrupted, orig)
		// 修改DER头部标识
		corrupted[0] ^= 0xFF
		corrupted[5] ^= 0xAA
		return corrupted
	}
	return orig
}
