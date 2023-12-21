package controllers

import (
	"encoding/json"
	"io"

	"github.com/labstack/echo/v4"
	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/views"
	"github.com/pkg/errors"
)

type (
	handlerFuncWithBody[T any] func(ctx echo.Context, body T) error
)

func withValidJsonBody[T any](hFunc handlerFuncWithBody[T]) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		return handlerWithJsonBodyFunction(ctx, hFunc)
	}
}

func handlerWithJsonBodyFunction[T any](ctx echo.Context, hFunc handlerFuncWithBody[T]) error {
	var err error
	var newBody *T = new(T)

	//bodyInstance := new(T)
	//newBody = *bodyInstance // if body instance is **T

	if err := ctx.Bind(newBody); err != nil {
		return errs.InvalidJsonError{}
	}
	/*
		err = ParseJSON(r.Body, &newBody)
		if err != nil {
			return apperrors.InvalidJsonError{}
		}
	*/

	newBody, err = doValidate(newBody)
	if err != nil {
		return errs.InvalidJsonError{}
	}

	return hFunc(ctx, *newBody)
}

func doValidate[T any](input *T) (*T, error) {
	var err error
	var inp = (*input) // in case of **T
	err = views.ValidateBody(inp)
	return &inp, errors.Wrap(err, "validation")
}

func ParseJSON(body io.Reader, v interface{}) error {
	return json.NewDecoder(body).Decode(&v)
}

/*
func withContextParam(ctx echo.Context, paramKey, paramValue string) {
	ctx.Set(paramKey, paramValue)
}
*/
