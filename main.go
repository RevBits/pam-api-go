package main

import (
	"fmt"
	"github.com/RevBits/pam-api-go/client"
	"github.com/joho/godotenv"
	"log"
	"os"
)

func main()  {
	fmt.Println("hello from go")
	err := godotenv.Load()
	if err != nil{
		log.Println("err while loading .env file")
	}
	partnerDomain := os.Getenv("PARTNER_DOMAIN")
	secretID := os.Getenv("SECRET_ID")
	apikey := os.Getenv("API_KEY")
	fmt.Println(partnerDomain, secretID, apikey)
	fmt.Println(GetPamSecret(partnerDomain, secretID, apikey))
}

//GetPamSecret This will fetch the secret value against secret id of given partner domain and apikey
func GetPamSecret(partnerDomain, secretId, apiKey string) (interface{}, error)  {
	secretValue, err := client.PamSecretValue(partnerDomain, secretId, apiKey)
	if err != nil{
		log.Println(err)
		return "", err
	}
	return secretValue, nil
}
