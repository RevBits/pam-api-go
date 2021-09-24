package client

import (
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"log"
	"os"
	"testing"
)

type Config struct {
	domain string
	secretId string
	apiKey string
}

func setUpTestDATA() *Config {
	err := godotenv.Load("../.env")
	if err != nil{
		log.Println("err while loading .env file")
	}
	c := &Config{
		domain: os.Getenv("PARTNER_DOMAIN"),
		secretId:  os.Getenv("SECRET_ID"),
		apiKey: os.Getenv("API_KEY"),
	}
	return c
}

func TestPamSecretValue(t *testing.T) {
	config := setUpTestDATA()
	value, err := PamSecretValue(config.domain, config.secretId, config.apiKey)
	if err != nil{
		t.Log(err)
	}
	assert.Equal(t, "PASSWORd", value)
}
