package services

import (
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
)

func Wire() {
	booksRepository := di.Get[models.BooksRepository]()
	refreshTokensRepository := di.Get[models.RefreshTokensRepository]()
	usersRepository := di.Get[models.UsersRepository]()
	var appConfig *configuration.AppConfig = di.Get[*configuration.AppConfig]()

	var booksService BooksService = NewBooksServiceImpl(booksRepository)
	di.Register(booksService)

	var tokensService TokensService = NewTokensServiceImpl(appConfig.GetPrivateKey(), appConfig.GetPublicKey(), refreshTokensRepository, usersRepository)
	di.Register(tokensService)

	var authService AuthService = NewAuthServiceImpl(usersRepository, refreshTokensRepository, tokensService)
	di.Register(authService)
}
