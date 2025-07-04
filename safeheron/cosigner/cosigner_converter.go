package cosigner

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/donutnomad/safeheron-api-sdk-go/safeheron/utils"
)

type CoSignerConverter struct {
	Config CoSignerConfig
}

func (c *CoSignerConfig) getApprovalCallbackServicePrivateKey() ([]byte, error) {
	//Supports both approvalCallbackServicePrivateKey and bizPrivKey
	if c.ApprovalCallbackServicePrivateKey == "" {
		c.ApprovalCallbackServicePrivateKey = c.BizPrivKey
	}
	k := c.ApprovalCallbackServicePrivateKey
	if c.LoadFromFile {
		return os.ReadFile(k)
	} else {
		return []byte(k), nil
	}
}

func (c *CoSignerConfig) getCoSignerPubKey() ([]byte, error) {
	//Supports both coSignerPubKey and apiPublKey
	if c.CoSignerPubKey == "" {
		c.CoSignerPubKey = c.ApiPubKey
	}
	k := c.CoSignerPubKey

	if c.LoadFromFile {
		return os.ReadFile(k)
	} else {
		return []byte(k), nil
	}
}

type CoSignerConfig struct {
	CoSignerPubKey                    string `comment:"coSignerPubKey"`
	ApprovalCallbackServicePrivateKey string `comment:"approvalCallbackServicePrivateKey"`
	ApiPubKey                         string `comment:"apiPubKey"`
	BizPrivKey                        string `comment:"bizPrivKey"`
	LoadFromFile                      bool
}

type CoSignerCallBack struct {
	Timestamp  string `json:"timestamp"`
	Sig        string `json:"sig"`
	Key        string `json:"key"`
	BizContent string `json:"bizContent"`
	RsaType    string `json:"rsaType"`
	AesType    string `json:"aesType"`
}

type CoSignerCallBackV3 struct {
	Timestamp  string `json:"timestamp"`
	Sig        string `json:"sig"`
	Version    string `json:"version"`
	BizContent string `json:"bizContent"`
}

func (c *CoSignerConverter) RequestConvert(d CoSignerCallBack) (string, error) {
	responseStringMap := map[string]string{
		"key":        d.Key,
		"timestamp":  d.Timestamp,
		"bizContent": d.BizContent,
	}
	coSignerPubKey, err := c.Config.getCoSignerPubKey()
	if err != nil {
		return "", err
	}
	// Verify sign
	verifyRet := utils.VerifySignWithRSA(serializeParams(responseStringMap), d.Sig, coSignerPubKey)
	if !verifyRet {
		return "", errors.New("CoSignerCallBack signature verification failed")
	}
	callbackServicePrivateKey, err := c.Config.getApprovalCallbackServicePrivateKey()
	if err != nil {
		return "", err
	}
	// Use your RSA private key to decrypt response's aesKey and aesIv
	var plaintext []byte
	if d.RsaType == utils.ECB_OAEP {
		plaintext, _ = utils.DecryptWithOAEP(d.Key, callbackServicePrivateKey)
	} else {
		plaintext, _ = utils.DecryptWithRSA(d.Key, callbackServicePrivateKey)
	}
	resAesKey := plaintext[:32]
	resAesIv := plaintext[32:]
	// Use AES to decrypt bizContent
	ciphertext, _ := base64.StdEncoding.DecodeString(d.BizContent)
	var callBackContent []byte
	if d.AesType == utils.GCM {
		callBackContent, _ = utils.NewGCMDecrypter(resAesKey, resAesIv, ciphertext)
	} else {
		callBackContent, _ = utils.NewCBCDecrypter(resAesKey, resAesIv, ciphertext)
	}
	return string(callBackContent), nil
}

func (c *CoSignerConverter) RequestV3Convert(d CoSignerCallBackV3) (string, error) {
	responseStringMap := map[string]string{
		"version":    "v3",
		"timestamp":  d.Timestamp,
		"bizContent": d.BizContent,
	}
	coSignerPubKey, err := c.Config.getCoSignerPubKey()
	if err != nil {
		return "", err
	}
	// Verify sign
	verifyRet := utils.VerifySignWithRSAPSS(serializeParams(responseStringMap), d.Sig, coSignerPubKey)
	if !verifyRet {
		return "", errors.New("CoSignerCallBack signature verification failed")
	}
	callBackContent, _ := base64.StdEncoding.DecodeString(d.BizContent)
	return string(callBackContent), nil
}

func (c *CoSignerConverter) ResponseV3Converter(d any) (map[string]string, error) {
	// Create params map
	params := map[string]string{
		"timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10),
		"code":      "200",
		"version":   "v3",
		"message":   "SUCCESS",
	}
	if d != nil {
		payLoad, _ := json.Marshal(d)
		params["bizContent"] = base64.StdEncoding.EncodeToString(payLoad)
	}
	callbackServicePrivateKey, err := c.Config.getApprovalCallbackServicePrivateKey()
	if err != nil {
		return nil, err
	}
	// Sign the request data with your Approval Callback Service's private Key
	signature, err := utils.SignParamsWithRSAPSS(serializeParams(params), callbackServicePrivateKey)
	if err != nil {
		return nil, err
	}
	params["sig"] = signature
	return params, nil
}

type CoSignerResponse struct {
	Approve bool   `json:"approve"`
	TxKey   string `json:"txKey"`
}

type CoSignerResponseV3 struct {
	Action     string `json:"action"`
	ApprovalId string `json:"approvalId"`
}

// It has been Deprecated,Please use convertCoSignerResponseWithNewCryptoType
func (c *CoSignerConverter) ResponseConverter(d any) (map[string]string, error) {
	// Use AES to encrypt request data
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	aesIv := make([]byte, 16)
	rand.Read(aesIv)
	// Create params map
	params := map[string]string{
		"timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10),
		"code":      "200",
		"message":   "SUCCESS",
	}
	if d != nil {
		payLoad, _ := json.Marshal(d)
		data := string(payLoad)
		encryptBizContent, err := utils.EncryContentWithAES(data, aesKey, aesIv)
		if err != nil {
			return nil, err
		}
		params["bizContent"] = encryptBizContent
	}

	coSignerPubKey, err := c.Config.getCoSignerPubKey()
	if err != nil {
		return nil, err
	}
	// Use Safeheron RSA public key to encrypt request's aesKey and aesIv
	encryptedKeyAndIv, err := utils.EncryptWithRSA(append(aesKey, aesIv...), coSignerPubKey)
	if err != nil {
		return nil, err
	}
	params["key"] = encryptedKeyAndIv
	callbackServicePrivateKey, err := c.Config.getApprovalCallbackServicePrivateKey()
	if err != nil {
		return nil, err
	}
	// Sign the request data with your RSA private key
	signature, err := utils.SignParamsWithRSA(serializeParams(params), callbackServicePrivateKey)
	if err != nil {
		return nil, err
	}
	params["sig"] = signature
	return params, nil
}

func (c *CoSignerConverter) ResponseConverterWithNewCryptoType(d any) (map[string]string, error) {
	// Use AES to encrypt request data
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	aesIv := make([]byte, 16)
	rand.Read(aesIv)
	// Create params map
	params := map[string]string{
		"timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10),
		"code":      "200",
		"message":   "SUCCESS",
	}
	if d != nil {
		payLoad, _ := json.Marshal(d)
		data := string(payLoad)
		encryptBizContent, err := utils.EncryContentWithAESGCM(data, aesKey, aesIv)
		if err != nil {
			return nil, err
		}
		params["bizContent"] = encryptBizContent
	}

	coSignerPubKey, err := c.Config.getCoSignerPubKey()
	if err != nil {
		return nil, err
	}
	// Use Safeheron RSA public key to encrypt request's aesKey and aesIv
	encryptedKeyAndIv, err := utils.EncryptWithOAEP(append(aesKey, aesIv...), coSignerPubKey)
	if err != nil {
		return nil, err
	}
	params["key"] = encryptedKeyAndIv
	callbackServicePrivateKey, err := c.Config.getApprovalCallbackServicePrivateKey()
	if err != nil {
		return nil, err
	}
	// Sign the request data with your RSA private key
	signature, err := utils.SignParamsWithRSA(serializeParams(params), callbackServicePrivateKey)
	if err != nil {
		return nil, err
	}
	params["sig"] = signature
	params["rsaType"] = utils.ECB_OAEP
	params["aesType"] = utils.GCM
	return params, nil
}

func serializeParams(params map[string]string) string {
	// Sort by key and serialize all request param into apiKey=...&bizContent=... format
	var data []string
	for k, v := range params {
		data = append(data, strings.Join([]string{k, v}, "="))
	}
	sort.Strings(data)
	return strings.Join(data, "&")
}
