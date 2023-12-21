package models

import (
	"context"
	"time"

	"github.com/gofrs/uuid"
)

type Book struct {
	Id        string
	Title     string
	Author    string
	CreatedAt time.Time
}

type BooksRepository interface {
	Create(ctx context.Context, title, author string) (*Book, error)
	GetById(ctx context.Context, id string) (*Book, error)
	GetByTitle(ctx context.Context, title string) (*Book, error)
	DeleteById(ctx context.Context, id string) error
}

type BooksRepositoryImpl struct {
	storage map[string]Book
}

func NewBooksRepositoryImpl() *BooksRepositoryImpl {
	p := new(BooksRepositoryImpl)
	p.storage = make(map[string]Book)
	return p
}

func (s *BooksRepositoryImpl) Create(ctx context.Context, title, author string) (*Book, error) {
	book := Book{
		Id:        uuid.Must(uuid.NewV4()).String(),
		Title:     title,
		Author:    author,
		CreatedAt: time.Now(),
	}

	s.storage[book.Id] = book

	return &book, nil
}

func (s *BooksRepositoryImpl) GetById(ctx context.Context, id string) (*Book, error) {
	book, ok := s.storage[id]
	if !ok {
		return nil, ErrNotFound
	}

	return &book, nil
}

func (s *BooksRepositoryImpl) GetByTitle(ctx context.Context, title string) (*Book, error) {
	for _, book := range s.storage {
		if book.Title == title {
			return &book, nil
		}
	}

	return nil, ErrNotFound
}

func (s *BooksRepositoryImpl) DeleteById(ctx context.Context, id string) error {
	_, ok := s.storage[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.storage, id)

	return nil
}
