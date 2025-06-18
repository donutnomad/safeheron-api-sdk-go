package webhook

import (
	"encoding/base64"
	"errors"
	"os"
	"sort"
	"strings"

	"github.com/donutnomad/safeheron-api-sdk-go/safeheron/utils"
)

type WebhookConverter struct {
	Config WebHookConfig
}

type WebHookConfig struct {
	SafeheronWebHookRsaPublicKey string `comment:"safeheronWebHookRsaPublicKey"`
	WebHookRsaPrivateKey         string `comment:"webHookRsaPrivateKey"`
	LoadFromFile                 bool
}

func (c WebHookConfig) GetSafeheronWebHookRsaPublicKey() ([]byte, error) {
	if c.LoadFromFile {
		return os.ReadFile(c.SafeheronWebHookRsaPublicKey)
	} else {
		return []byte(c.SafeheronWebHookRsaPublicKey), nil
	}
}

func (c WebHookConfig) GetWebHookRsaPrivateKey() ([]byte, error) {
	if c.LoadFromFile {
		return os.ReadFile(c.WebHookRsaPrivateKey)
	} else {
		return []byte(c.WebHookRsaPrivateKey), nil
	}
}

type WebHook struct {
	Timestamp  string `json:"timestamp"`
	Sig        string `json:"sig"`
	Key        string `json:"key"`
	BizContent string `json:"bizContent"`
	RsaType    string `json:"rsaType"`
	AesType    string `json:"aesType"`
}

type WebHookResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *WebhookConverter) Convert(d WebHook) (string, error) {
	responseStringMap := map[string]string{
		"key":        d.Key,
		"timestamp":  d.Timestamp,
		"bizContent": d.BizContent,
	}
	sfRsaPublicKey, err := c.Config.GetSafeheronWebHookRsaPublicKey()
	if err != nil {
		return "", errors.New("parse webhook rsa public key failed")
	}
	rsaPrivateKey, err := c.Config.GetWebHookRsaPrivateKey()
	if err != nil {
		return "", errors.New("parse webhook rsa private key failed")
	}
	// Verify sign
	verifyRet := utils.VerifySignWithRSA(serializeParams(responseStringMap), d.Sig, sfRsaPublicKey)
	if !verifyRet {
		return "", errors.New("webhook signature verification failed")
	}
	// Use your RSA private key to decrypt response's aesKey and aesIv
	var plaintext []byte
	if d.RsaType == utils.ECB_OAEP {
		plaintext, _ = utils.DecryptWithOAEP(d.Key, rsaPrivateKey)
	} else {
		plaintext, _ = utils.DecryptWithRSA(d.Key, rsaPrivateKey)
	}

	resAesKey := plaintext[:32]
	resAesIv := plaintext[32:]
	// Use AES to decrypt bizContent
	ciphertext, _ := base64.StdEncoding.DecodeString(d.BizContent)
	var webHookContent []byte
	if d.AesType == utils.GCM {
		webHookContent, _ = utils.NewGCMDecrypter(resAesKey, resAesIv, ciphertext)
	} else {
		webHookContent, _ = utils.NewCBCDecrypter(resAesKey, resAesIv, ciphertext)
	}
	return string(webHookContent), nil
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
