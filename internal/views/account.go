package views

import (
	"github.com/leokuzmanovic/go-echo-example/api"
)

type CreateBookRequestValidated api.CreateBookRequest

func (r *CreateBookRequestValidated) SanitizeAndValidate() error {
	return ValidateBody(r)
}
