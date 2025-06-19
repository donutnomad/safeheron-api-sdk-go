package safeheron

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/donutnomad/safeheron-api-sdk-go/safeheron/utils"
)

type Client struct {
	Config    ApiConfig
	Logger    *slog.Logger
	Transport *http.Transport
}

type SafeheronResponse struct {
	Code       int64  `form:"code" json:"code"`
	Message    string `form:"message" json:"message"`
	Sig        string `form:"sig" json:"sig"`
	Key        string `form:"key" json:"key"`
	BizContent string `form:"bizContent" json:"bizContent"`
	Timestamp  string `form:"timestamp" json:"timestamp"`
	RsaType    string `form:"rsaType" json:"rsaType"`
	AesType    string `form:"aesType" json:"aesType"`
}

func (c *Client) SendRequest(request any, response any, path string) error {
	respContent, err := c.execute(request, path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(respContent, &response)
	return err
}

func (c *Client) logger() *slog.Logger {
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return c.Logger
}

func (c *Client) execute(request any, endpoint string) ([]byte, error) {
	// Use AES to encrypt request data
	aesKey := make([]byte, 32)
	_, _ = rand.Read(aesKey)
	aesIv := make([]byte, 16)
	_, _ = rand.Read(aesIv)
	// Create params map
	params := map[string]string{
		"apiKey":    c.Config.ApiKey,
		"timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10),
	}
	if request != nil {
		payLoad, _ := json.Marshal(request)
		data := string(payLoad)
		c.logger().Info("POST request", "url", fmt.Sprintf("%s%s", c.Config.BaseUrl, endpoint), "plain_data", data)
		encryptBizContent, err := utils.EncryContentWithAESGCM(data, aesKey, aesIv)
		if err != nil {
			return nil, err
		}
		params["bizContent"] = encryptBizContent
	}

	safeheronRsaPublicKey, err := c.Config.GetSafeheronRsaPublicKey()
	if err != nil {
		return nil, err
	}
	pk, err := c.Config.GetRsaPrivateKey()
	if err != nil {
		return nil, err
	}

	// Use Safeheron RSA public key to encrypt request's aesKey and aesIv
	encryptedKeyAndIv, err := utils.EncryptWithOAEP(append(aesKey, aesIv...), safeheronRsaPublicKey)
	if err != nil {
		return nil, err
	}
	params["key"] = encryptedKeyAndIv

	// Sign the request data with your RSA private key
	signature, err := utils.SignParamsWithRSA(serializeParams(params), pk)
	if err != nil {
		return nil, err
	}
	params["sig"] = signature
	params["rsaType"] = utils.ECB_OAEP
	params["aesType"] = utils.GCM

	// Send post
	safeheronResponse, _ := c.Post(params, endpoint)

	// Decode json data into SafeheronResponse struct
	var responseStruct SafeheronResponse
	json.Unmarshal(safeheronResponse, &responseStruct)
	if responseStruct.Code != 200 {
		c.logger().Warn("request failed", "url", fmt.Sprintf("%s%s", c.Config.BaseUrl, endpoint), "code", responseStruct.Code, "message", responseStruct.Message)
		return nil, fmt.Errorf("request failed, code: %d, message: %s", responseStruct.Code, responseStruct.Message)
	}

	responseStringMap := map[string]string{
		"code":       strconv.FormatInt(responseStruct.Code, 10),
		"message":    responseStruct.Message,
		"key":        responseStruct.Key,
		"timestamp":  responseStruct.Timestamp,
		"bizContent": responseStruct.BizContent,
	}

	// Verify sign
	verifyRet := utils.VerifySignWithRSA(serializeParams(responseStringMap), responseStruct.Sig, safeheronRsaPublicKey)
	if !verifyRet {
		return nil, errors.New("response signature verification failed")
	}

	// Use your RSA private key to decrypt response's aesKey and aesIv
	//fmt.Printf(responseStruct.Key)

	var plaintext []byte
	if utils.ECB_OAEP == responseStruct.RsaType {
		plaintext, _ = utils.DecryptWithOAEP(responseStruct.Key, pk)
	} else {
		plaintext, _ = utils.DecryptWithRSA(responseStruct.Key, pk)
	}
	resAesKey := plaintext[:32]
	resAesIv := plaintext[32:]
	// Use AES to decrypt bizContent
	ciphertext, _ := base64.StdEncoding.DecodeString(responseStruct.BizContent)
	var respContent []byte
	if utils.GCM == responseStruct.AesType {
		respContent, _ = utils.NewGCMDecrypter(resAesKey, resAesIv, ciphertext)
	} else {
		respContent, _ = utils.NewCBCDecrypter(resAesKey, resAesIv, ciphertext)
	}
	c.logger().Info("POST request Response", "url", fmt.Sprintf("%s%s", c.Config.BaseUrl, endpoint), "plain_data", string(respContent))

	return respContent, nil
}

func (c *Client) Post(params map[string]string, path string) ([]byte, error) {
	fullPath := fmt.Sprintf("%s%s", c.Config.BaseUrl, path)
	jsonValue, _ := json.Marshal(params)
	c.logger().Debug("POST request(encrypt)", "url", fullPath, "encrypt_data", string(jsonValue))

	var transport *http.Transport
	if c.Transport != nil {
		transport = c.Transport
	} else {
		transport = &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		}
	}

	var httpClient *http.Client
	if c.Config.RequestTimeout != 0 {
		httpClient = &http.Client{Transport: transport, Timeout: time.Duration(c.Config.RequestTimeout) * time.Millisecond}
	} else {
		httpClient = &http.Client{Transport: transport, Timeout: 20 * time.Second}
	}
	resp, err := httpClient.Post(fullPath, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		c.logger().Error("POST request safeheron api response", "url", path, "statusCode", resp.StatusCode, "status", resp.Status)
		return nil, fmt.Errorf("POST request safeheron api response, statusCode: %d, status: %s", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger().Error("request safeheron api error", "url", path, "statusCode", resp.StatusCode, "status", resp.Status, "err", err)
		return nil, err
	}
	c.logger().Debug("POST request Response(encrypt)", "url", fullPath, "encrypt_data", string(body))

	return body, nil
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
