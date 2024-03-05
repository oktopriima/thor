package jwt_test

import (
	"github.com/bluele/go-timecop"
	"github.com/oktopriima/thor/jwt"
	. "gopkg.in/check.v1"
	"testing"
	"time"
)

type S struct{}

func Test(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&S{})

var request = jwt.Request{
	SignatureKey: "test-environment",
	Audience:     "http://localhost:8000",
	Issuer:       "http://localhost:8080",
}

var params = jwt.Params{
	ID: "101",
}

var (
	errToken     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiIxIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMCIsImNyZSI6MTcwOTYyOTQ0ODEwNDQwMTQwMCwiZXhwIjoxNzA5NjM2NjQ4MTA0NDAxNDAwLCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo4MDAwIiwib2JqIjp7IkN1c3RvbUZpZWxkIjoidGVzdC10aGlzLWlzLWN1c3RvbSJ9fQ.f34SmKqN3agFSOsRrM-8vLxyc-onCtDB-wF4_qC7QWc"
	errSignature = "test-signature"
)

func (s *S) TestInvalidAccessToken(c *C) {
	t := jwt.NewAccessToken(request, 3600)

	token, err := t.GenerateToken(params)
	c.Assert(err, IsNil)

	// assert extraction
	e, err := jwt.Extract(token.GetStringToken(), request.SignatureKey)

	c.Assert(err, IsNil)
	c.Assert(e.Aud, DeepEquals, request.Audience)
	c.Assert(e.Iss, DeepEquals, request.Issuer)
	c.Assert(e.Exp, FitsTypeOf, int64(0))
	c.Assert(e.Cre, FitsTypeOf, int64(0))
	c.Assert(e.Obj, DeepEquals, params.Obj)
	c.Assert(e.Id, DeepEquals, params.ID)

	// travel to 3 hour ahead
	timecop.Travel(time.Now().Add(3 * time.Hour))

	v := t.Validate(token.GetStringToken())
	c.Assert(v, FitsTypeOf, true)
	c.Assert(v, Equals, false)

	timecop.Return()
}

func (s *S) TestValidAccessToken(c *C) {
	t := jwt.NewAccessToken(request, 3600)

	token, err := t.GenerateToken(params)
	c.Assert(err, IsNil)

	// assert extraction
	e, err := jwt.Extract(token.GetStringToken(), request.SignatureKey)

	c.Assert(err, IsNil)
	c.Assert(e.Aud, DeepEquals, request.Audience)
	c.Assert(e.Iss, DeepEquals, request.Issuer)
	c.Assert(e.Exp, FitsTypeOf, int64(0))
	c.Assert(e.Cre, FitsTypeOf, int64(0))
	c.Assert(e.Obj, DeepEquals, params.Obj)
	c.Assert(e.Id, DeepEquals, params.ID)

	v := t.Validate(token.GetStringToken())
	c.Assert(v, FitsTypeOf, true)
	c.Assert(v, Equals, true)
}

func (s *S) TestValidationWithWrongToken(c *C) {
	t := jwt.NewAccessToken(request, 3600)

	_, err := jwt.Extract(errToken, request.SignatureKey)
	c.Assert(err, NotNil)

	c.Assert(err.Error(), Equals, "error parse token")

	v := t.Validate(errToken)
	c.Assert(v, Equals, false)
}

func (s *S) TestValidationWithWrongSignatureKey(c *C) {
	t := jwt.NewAccessToken(request, 3600)
	token, err := t.GenerateToken(params)
	c.Assert(err, IsNil)

	_, err = jwt.Extract(token.GetStringToken(), errSignature)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "error parse token")

	v := t.Validate(errToken)
	c.Assert(v, Equals, false)
}

func (s *S) TestExtractedWithWrongPayload(c *C) {
	var localParams = struct {
		Token string
		Key   string
		Id    string
		jwt.Request
	}{
		Token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJhdWRpZW5jZSI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcmVhdGVkX2F0IjoxNzA5NjI5NDQ4MTA0NDAxNDAwLCJleHBpcmVkX2F0IjoxNzA5NjM2NjQ4MTA0NDAxNDAwLCJpc3N1ZXIiOiJodHRwczovL2xvY2FsaG9zdDo4MDAwIiwib2JqZWN0Ijp7IkN1c3RvbUZpZWxkIjoidGVzdC10aGlzLWlzLWN1c3RvbSJ9fQ.sDotkcKN9_XMLFvwIaZWgmPxLrW_vLnA2YZWXr8wvrg",
		Key:     request.SignatureKey,
		Id:      params.ID,
		Request: request,
	}

	t := jwt.NewAccessToken(localParams.Request, 3600)

	e, err := jwt.Extract(localParams.Token, localParams.Key)
	c.Assert(err, IsNil)

	c.Assert(e.Id, Equals, "")
	c.Assert(e.Cre, Equals, int64(0))
	c.Assert(e.Exp, Equals, int64(0))
	c.Assert(e.Obj, IsNil)
	c.Assert(e.Iss, Equals, "")
	c.Assert(e.Aud, Equals, "")

	v := t.Validate(localParams.Token)
	c.Assert(v, Equals, false)
}
