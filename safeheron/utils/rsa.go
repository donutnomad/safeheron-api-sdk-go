package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

const ECB_OAEP = "ECB_OAEP"

func SignParamsWithRSA(data string, privateKeyData []byte) (string, error) {
	// Sign data with your RSA private key
	privateKey, err := parsePrivateKey(privateKeyData)
	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	// Encode to base64 format
	b64sig := base64.StdEncoding.EncodeToString(signature)
	return b64sig, err
}

func SignParamsWithRSAPSS(data string, privateKeyData []byte) (string, error) {
	// Sign data with your RSA private key
	privateKey, err := parsePrivateKey(privateKeyData)
	if err != nil {
		return "", err
	}
	hashed := sha256.Sum256([]byte(data))

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})

	if err != nil {
		return "", err
	}
	// Encode to base64 format
	b64sig := base64.StdEncoding.EncodeToString(signature)
	return b64sig, err
}

func DecryptWithRSA(base64Data string, privateKeyData []byte) ([]byte, error) {
	privateKey, err := parsePrivateKey(privateKeyData)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DecryptWithOAEP(base64Data string, privateKeyData []byte) ([]byte, error) {
	privateKey, err := parsePrivateKey(privateKeyData)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func EncryptWithRSA(data []byte, publicKeyData []byte) (string, error) {
	pubKey, err := parsePublicKey(publicKeyData)
	if err != nil {
		return "", err
	}
	signPKCS1v15, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	if err != nil {
		return "", err
	}
	// Base64 encode
	ciphertext := base64.StdEncoding.EncodeToString(signPKCS1v15)
	return ciphertext, nil
}

func EncryptWithOAEP(data []byte, publicKeyData []byte) (string, error) {
	pubKey, err := parsePublicKey(publicKeyData)
	if err != nil {
		return "", err
	}
	signPKOAEP, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data, nil)
	if err != nil {
		return "", err
	}
	// Base64 encode
	ciphertext := base64.StdEncoding.EncodeToString(signPKOAEP)
	return ciphertext, nil
}

func VerifySignWithRSA(data string, base64Sign string, rasPublicKeyData []byte) bool {
	sign, err := base64.StdEncoding.DecodeString(base64Sign)
	if err != nil {
		return false
	}

	publicKey, err := parsePublicKey(rasPublicKeyData)
	if err != nil {
		return false
	}

	hashed := sha256.Sum256([]byte(data))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], sign)
	return err == nil
}

func VerifySignWithRSAPSS(data string, base64Sign string, rasPublicKeyData []byte) bool {
	sign, err := base64.StdEncoding.DecodeString(base64Sign)
	if err != nil {
		return false
	}

	publicKey, err := parsePublicKey(rasPublicKeyData)
	if err != nil {
		return false
	}

	hashed := sha256.Sum256([]byte(data))
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], sign, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	return err == nil
}

func parsePublicKey(data []byte) (*rsa.PublicKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("Could not read public key. Please make sure the file in pem format, with headers and footers.(e.g. '-----BEGIN PUBLIC KEY-----' and '-----END PUBLIC KEY-----')")
	}
	var pkixPublicKey interface{}
	if pemBlock.Type == "RSA PUBLIC KEY" {
		// -----BEGIN RSA PUBLIC KEY-----
		pkixPublicKey, _ = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	} else if pemBlock.Type == "PUBLIC KEY" {
		// -----BEGIN PUBLIC KEY-----
		pkixPublicKey, _ = x509.ParsePKIXPublicKey(pemBlock.Bytes)
	}
	publicKey := pkixPublicKey.(*rsa.PublicKey)
	return publicKey, nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("Could not read private key. Please make sure the file in pem format, with headers and footers.(e.g. '-----BEGIN PRIVATE KEY-----' and '-----END PRIVATE KEY-----')")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	return privateKey.(*rsa.PrivateKey), err
}
