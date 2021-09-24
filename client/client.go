package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"time"
)

const (
	prime     = 23
	generated = 9
	randMin   = 2
	randMax   = 9
)

const pamUrlTemplate = "https://%v/api/v1/secretman/GetSecretV2/%v"

type PAMResponse struct {
	Key        string `json:"key"`
	KeyA       int    `json:"keyA"`
	KeyB       int    `json:"keyB"`
	Value      string `json:"value"`
	ErrMessage string `json:"errorMessage"`
}

func decrypt(encrypted, passphrase string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	if len(ct) < 16 || string(ct[:8]) != "Salted__" {
		return "", errors.New("invalid text length")
	}

	salt := ct[8:16]
	ct = ct[16:]
	key, iv := __deriveKeyAndIv(passphrase, string(salt))

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.New(fmt.Sprintf("unable to create new cipher, err : %v", err))
	}

	cbc := cipher.NewCBCDecrypter(block, []byte(iv))
	dst := make([]byte, len(ct))
	cbc.CryptBlocks(dst, ct)

	return string(__pKCS7Trimming(dst)), nil
}

func __pKCS7Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func __deriveKeyAndIv(passphrase string, salt string) (string, string) {
	salted := ""
	dI := ""

	for len(salted) < 48 {
		md := md5.New()
		md.Write([]byte(dI + passphrase + salt))
		dM := md.Sum(nil)
		dI = string(dM[:16])
		salted = salted + dI
	}

	key := salted[0:32]
	iv := salted[32:48]

	return key, iv
}

//PamSecretValue This will fetch the secret value against secret id of given partner domain and apikey
func PamSecretValue(partnerDomain, secretId, apiKey string) (interface{}, error) {

	body := bytes.NewBuffer([]byte{})
	//url := "https://" + partnerDomain + "/api/v1/secretman/GetSecretV2/" + secretId
	url := fmt.Sprintf(pamUrlTemplate, partnerDomain, secretId)
	req, err := http.NewRequest("GET", url , body)

	log.Printf("[DEBUG] calling %s", req.URL.String())

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ENPAST Jenkins Client")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apiKey", apiKey)
	//req.Header.Set("publicKey", publicKey)

	rand.Seed(time.Now().UnixNano())
	pvtKeyA := rand.Intn(randMax-randMin) + randMin
	rand.Seed(time.Now().UnixNano())
	pvtKeyB := rand.Intn(randMax-randMin) + randMin

	pbKeyA := int(math.Pow(float64(generated), float64(pvtKeyA))) % prime
	pbKeyB := int(math.Pow(float64(generated), float64(pvtKeyB))) % prime

	req.Header.Set("publicKeyA", fmt.Sprintf("%v", pbKeyA))
	req.Header.Set("publicKeyB", fmt.Sprintf("%v", pbKeyB))


	client := &http.Client{}
	res, err := client.Do(req)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to do req, API_KEY : %v , err : %v", apiKey, err))
	}

	var pam_data PAMResponse

	if err = json.NewDecoder(res.Body).Decode(&pam_data); err != nil {
		return nil, err
	}

	if pam_data.ErrMessage != "" {
		return nil, errors.New(fmt.Sprintf("pam returned error  err : %v", pam_data.ErrMessage))
	}

	sharedKeyA := math.Mod(math.Pow(float64(pam_data.KeyA), float64(pvtKeyA)), prime)
	sharedKeyB := math.Mod(math.Pow(float64(pam_data.KeyB), float64(pvtKeyB)), prime)

	var i, e = big.NewInt(int64(sharedKeyA)), big.NewInt(int64(sharedKeyB))
	i.Exp(i, e, nil)

	secret := fmt.Sprintf("%d", i)
	log.Printf("[INFO] secret : %v\n", secret)
	val, err := decrypt(pam_data.Value, secret)
	if err != nil {
		return nil, err
	}

	log.Printf("val : %v\n", val)
	fmt.Println(val)

	return val, nil
}


