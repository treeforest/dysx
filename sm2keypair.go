package dysx

import (
	"encoding/json"

	"github.com/pkg/errors"
	tjsm2 "github.com/tjfoc/gmsm/sm2"
	bcx509 "github.com/tjfoc/gmsm/x509"
)

// SM2KeyPairCollection SM2密钥对集合
type SM2KeyPairCollection struct {
	Pairs []SM2KeyPair
}

// SM2KeyPair 单个SM2密钥对条目
type SM2KeyPair struct {
	Index uint32            // 密钥索引（1起始）
	Key   *tjsm2.PrivateKey // SM2私钥对象
}

// serializedKeyPair 序列化中间结构
type serializedKeyPair struct {
	Index  uint32 `json:"index"`
	KeyPem []byte `json:"keyPem"`
}

func NewSM2KeyPairCollection(pairs ...SM2KeyPair) *SM2KeyPairCollection {
	return &SM2KeyPairCollection{
		Pairs: pairs,
	}
}

func NewSM2KeyPair(index uint32, key *tjsm2.PrivateKey) SM2KeyPair {
	return SM2KeyPair{
		Index: index,
		Key:   key,
	}
}

// Serialize 序列化为JSON格式字节
func (c SM2KeyPairCollection) Serialize() ([]byte, error) {
	output := make([]serializedKeyPair, 0, len(c.Pairs))

	for _, p := range c.Pairs {
		if p.Key == nil {
			return nil, errors.Errorf("空私钥 @索引%d", p.Index)
		}

		pemData, err := bcx509.WritePrivateKeyToPem(p.Key, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "PEM编码失败 @索引%d", p.Index)
		}

		output = append(output, serializedKeyPair{
			Index:  p.Index,
			KeyPem: pemData,
		})
	}

	return json.Marshal(output)
}

// Deserialize 从JSON数据反序列化
func (c *SM2KeyPairCollection) Deserialize(data []byte) error {
	if len(data) == 0 {
		return errors.New("空输入数据")
	}

	var input []serializedKeyPair
	if err := json.Unmarshal(data, &input); err != nil {
		return errors.Wrap(err, "JSON解析失败")
	}

	c.Pairs = make([]SM2KeyPair, 0, len(input))

	for _, item := range input {
		key, err := bcx509.ReadPrivateKeyFromPem(item.KeyPem, nil)
		if err != nil {
			return errors.Wrapf(err, "私钥解析失败 @索引%d", item.Index)
		}

		c.Pairs = append(c.Pairs, SM2KeyPair{
			Index: item.Index,
			Key:   key,
		})
	}

	return nil
}
