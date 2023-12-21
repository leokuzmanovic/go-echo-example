package models

import (
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
)

func Wire() {
	var booksRepository BooksRepository = NewBooksRepositoryImpl()
	di.Register(booksRepository)

	var tokensRepository TokensRepository = NewTokensRepositoryImpl()
	di.Register(tokensRepository)

	var usersRepository UsersRepository = NewUsersRepositoryImpl()
	di.Register(usersRepository)
}
