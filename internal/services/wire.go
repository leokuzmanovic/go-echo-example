package services

import (
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
)

func Wire() {
	booksRepository := di.Get[models.BooksRepository]()
	tokensRepository := di.Get[models.TokensRepository]()
	usersRepository := di.Get[models.UsersRepository]()
	var appConfig *configuration.AppConfig = di.Get[*configuration.AppConfig]()

	var booksService BooksService = NewBooksServiceImpl(booksRepository)
	di.Register(booksService)

	var tokensService TokensService = NewTokensServiceImpl(appConfig.GetPrivateKey(), appConfig.GetPublicKey(), tokensRepository, usersRepository)
	di.Register(tokensService)

	var authService AuthService = NewAuthServiceImpl(usersRepository, tokensRepository, tokensService)
	di.Register(authService)
}
