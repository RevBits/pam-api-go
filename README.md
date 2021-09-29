# PAM Client
This repo serve as pam client for fetching secret credentials

# Usage

```
import (
    "fmt"
    "github.com/RevBits/pam-api-go/client"
)

func main() {
	secretValue, err := client.PamSecretValue("Domain", "SecretID", "ApiKey")
	fmt.Println(secretValue) 
}
```