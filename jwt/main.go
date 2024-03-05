package jwt

import (
	"fmt"
	"github.com/bluele/go-timecop"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"time"
)

const DefaultDuration int64 = 3600
const TimeTinyFormat = "20060102150405"

type accessToken struct {
	SignatureKey []byte
	Duration     int64
	Audience     string
	Issuer       string
}

func (a *accessToken) Validate(token string) bool {
	e, err := Extract(token, string(a.SignatureKey))
	if err != nil {
		return false
	}

	return e.Iss == a.Issuer && e.Aud == a.Audience && timecop.Now().Before(time.Unix(0, e.Exp))
}

type AccessToken interface {
	GenerateToken(request Params) (TokenResponse, error)
	GenerateFromRefresh(token, refreshToken string, renew bool) (TokenResponse, error)
	Validate(token string) bool
}

func NewAccessToken(req Request, duration ...int64) AccessToken {
	dur := DefaultDuration
	if len(duration) > 0 {
		dur = duration[0]
	}

	return &accessToken{
		SignatureKey: []byte(req.SignatureKey),
		Duration:     dur,
		Issuer:       req.Issuer,
		Audience:     req.Audience,
	}
}

func (a *accessToken) GenerateToken(request Params) (TokenResponse, error) {
	t := jwt.New(jwt.SigningMethodHS256)
	claims := t.Claims.(jwt.MapClaims)

	now := time.Now()

	expiredAt := now.Add(time.Second * time.Duration(a.Duration))
	refreshToken, err := a.generateRefreshToken(now, request.ID)
	if err != nil {
		return nil, err
	}

	claims["_id"] = request.ID
	claims["obj"] = request.Obj
	claims["exp"] = expiredAt.UnixNano()
	claims["cre"] = now.UnixNano()
	claims["aud"] = a.Audience
	claims["iss"] = a.Issuer

	tokenString, err := t.SignedString(a.SignatureKey)
	if err != nil {
		return nil, err
	}

	return CreateResponse(tokenString, string(refreshToken), string(a.SignatureKey)), nil
}

func (a *accessToken) GenerateFromRefresh(oldToken, refreshToken string, renew bool) (TokenResponse, error) {
	return CreateResponse("", refreshToken, string(a.SignatureKey)), nil
}

func (a *accessToken) generateRefreshToken(now time.Time, id string) ([]byte, error) {
	hashed := fmt.Sprintf("%s-%s-%s", id, string(a.SignatureKey), now.Format(TimeTinyFormat))
	refreshToken, err := bcrypt.GenerateFromPassword([]byte(hashed), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return refreshToken, nil
}
