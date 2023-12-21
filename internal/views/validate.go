package views

import (
	"github.com/go-playground/validator/v10"
)

type ValidationRequest interface {
	SanitizeAndValidate() error
}

func ValidateBody(body interface{}) error {
	err := GetValidator().Struct(body)
	return err
	/*
		if err != nil {
			return &apierrors.FormValidationError{
				ValidateErr: err,
			}
		}
		return nil
	*/

}

func GetValidator() *validator.Validate {
	validate := validator.New()
	return validate
}
