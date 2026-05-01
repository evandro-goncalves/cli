package iso

import (
	"encoding/json"
	"fmt"
)

type ResponseInterface interface {
	Unmarshal(msg []byte) error
	Validate() error
	GetError() string
	GetMessage() string
	GetAccessToken() string
	GetResponse() interface{}
	GetEntity() interface{}
}

type BaseResponse struct {
	ID        string `json:"id,omitempty"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
	Signature string `json:"signature,omitempty"`
	Response  struct {
		Status    int    `json:"status,omitempty"`
		Message   string `json:"message,omitempty"`
		Error     bool   `json:"error,omitempty"`
		ErrorCode int    `json:"error_code,omitempty"`
	} `json:"response,omitempty"`
}

func (r *BaseResponse) Unmarshal(msg []byte) error {
	return json.Unmarshal(msg, r)
}

func (r *BaseResponse) Validate() error {
	if r.Error != "" {
		return fmt.Errorf("%s", r.Message)
	}
	if r.Response.Error {
		return fmt.Errorf("%s", r.Response.Message)
	}
	return nil
}

func (r *BaseResponse) GetError() string         { return r.Error }
func (r *BaseResponse) GetMessage() string       { return r.Message }
func (r *BaseResponse) GetAccessToken() string   { return r.Message }
func (r *BaseResponse) GetResponse() interface{} { return r.Response }
func (r *BaseResponse) GetEntity() interface{}   { return r.Response }

type Oauth2Response struct {
	BaseResponse
	Reason      string `json:"reason,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	AccessToken string `json:"access_token"`
}

func (r *Oauth2Response) Unmarshal(msg []byte) error {
	return json.Unmarshal(msg, r)
}

func (r *Oauth2Response) GetAccessToken() string { return r.AccessToken }
