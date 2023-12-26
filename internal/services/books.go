package services

import (
	"context"

	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
)

//go:generate mockery --name BooksService
type BooksService interface {
	CreateBook(ctx context.Context, title, author string) (*models.Book, error)
	GetBookById(ctx context.Context, id string) (*models.Book, error)
	DeleteBookById(ctx context.Context, id string) error
}

type BooksServiceImpl struct {
	booksRepository models.BooksRepository
}

func NewBooksServiceImpl(booksRepository models.BooksRepository) *BooksServiceImpl {
	p := new(BooksServiceImpl)
	p.booksRepository = booksRepository

	return p
}

func (s *BooksServiceImpl) CreateBook(ctx context.Context, title, author string) (*models.Book, error) {
	_, err := s.booksRepository.GetByTitle(ctx, title)
	if err != nil && err == models.ErrNotFound {
		return s.booksRepository.Create(ctx, title, author)
	} else if err != nil {
		return nil, err
	}
	return nil, errs.DublicatedEntityError{}
}

func (s *BooksServiceImpl) GetBookById(ctx context.Context, id string) (*models.Book, error) {
	book, err := s.booksRepository.GetById(ctx, id)
	if err != nil && err == models.ErrNotFound {
		return nil, errs.NotFoundError{}
	}
	return book, err
}

func (s *BooksServiceImpl) DeleteBookById(ctx context.Context, id string) error {
	return s.booksRepository.DeleteById(ctx, id)
}
