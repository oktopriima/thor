package jwt

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"time"
)

type Params struct {
	ID  string
	Obj interface{}
}

type Request struct {
	SignatureKey string
	Audience     string
	Issuer       string
}

type Response struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ExpiredAt    int64  `json:"expired_at"`
	CreatedAt    int64  `json:"created_at"`
	Audience     string `json:"audience"`
	Issuer       string `json:"issuer"`
}

func (r *Response) GetIssuer() string {
	return r.Issuer
}

func (r *Response) GetAudience() string {
	return r.Audience
}

func (r *Response) GetResponseObject() Response {
	return *r
}

func (r *Response) GetStringToken() string {
	return r.Token
}

func (r *Response) GetStringRefreshToken() string {
	return r.RefreshToken
}

func (r *Response) GetTimeExpiredAt() time.Time {
	return time.Unix(0, r.ExpiredAt)
}

func (r *Response) GetTimeCreatedAt() time.Time {
	return time.Unix(0, r.CreatedAt)
}

type TokenResponse interface {
	GetObject
	GetToken
	GetTime
	GetString
}

type GetToken interface {
	GetStringToken() string
	GetStringRefreshToken() string
}

type GetTime interface {
	GetTimeExpiredAt() time.Time
	GetTimeCreatedAt() time.Time
}

type GetObject interface {
	GetResponseObject() Response
}

type GetString interface {
	GetIssuer() string
	GetAudience() string
}

func CreateResponse(token, refreshToken, key string) TokenResponse {
	extract, err := Extract(token, key)
	if err != nil {
		log.Fatalf("error found %v", err)
	}
	return &Response{
		ExpiredAt:    extract.Exp,
		CreatedAt:    extract.Cre,
		Audience:     extract.Aud,
		Issuer:       extract.Iss,
		Token:        token,
		RefreshToken: refreshToken,
	}
}

type Extracted struct {
	Id  string      `json:"_id"`
	Iss string      `json:"iss"`
	Aud string      `json:"aud"`
	Cre int64       `json:"cre"`
	Exp int64       `json:"exp"`
	Obj interface{} `json:"obj"`
}

func Extract(token, key string) (*Extracted, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parse token")
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		jsonBody, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}

		resp := new(Extracted)
		if err := json.Unmarshal(jsonBody, resp); err != nil {
			return nil, err
		}

		return resp, nil
	}

	return nil, fmt.Errorf("invalid token")
}
