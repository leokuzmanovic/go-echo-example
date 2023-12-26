package controllers

import (
	"github.com/labstack/echo/v4"
)

type ContextEnricherMiddleware struct{}

func NewContextEnricherMiddleware() *ContextEnricherMiddleware {
	return &ContextEnricherMiddleware{}
}

func (s *ContextEnricherMiddleware) Apply(e *echo.Echo) {
	e.Use(s.Handle)
}

func (s *ContextEnricherMiddleware) Handle(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		/*
			NOTE: use this middleware to enrich the context with data from the request, i.e.:

			r := ctx.Request()
			r = r.WithContext(context.WithValue(r.Context(), "someKey", "someValue"))
			ctx.SetRequest(r)
		*/

		return next(ctx)
	}
}
