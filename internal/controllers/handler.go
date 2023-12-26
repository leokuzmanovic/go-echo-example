package controllers

import (
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
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
	var body *T = new(T)

	if err := ctx.Bind(body); err != nil {
		return errs.InvalidJsonError{}
	}

	body, err = validateBody(body)
	if err != nil {
		return errs.InvalidJsonError{}
	}

	return hFunc(ctx, *body)
}

func validateBody[T any](body *T) (*T, error) {
	validator := validator.New()
	err := validator.Struct(*body)
	return body, errors.Wrap(err, "validation")
}
