package models

import (
	"context"

	"github.com/gofrs/uuid"
)

const (
	USER1_USERNAME = "user1"
	USER1_PASSWORD = "pass1"
	USER2_USERNAME = "user2"
	USER2_PASSWORD = "pass2"
)

type User struct {
	Id       uuid.UUID
	Username string
	Password string
}

//go:generate mockery --name UsersRepository
type UsersRepository interface {
	ExistsById(ctx context.Context, userId uuid.UUID) (bool, error)
	Get(ctx context.Context, id uuid.UUID) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
}

type UsersRepositoryImpl struct {
	store map[uuid.UUID]User
}

func NewUsersRepositoryImpl() *UsersRepositoryImpl {
	p := new(UsersRepositoryImpl)
	p.store = make(map[uuid.UUID]User)
	//NOTE: for testing purposes
	user1Id := uuid.Must(uuid.FromString("00000000-0000-0000-0000-000000000001"))
	p.store[user1Id] = User{
		Id:       user1Id,
		Username: USER1_USERNAME,
		Password: USER1_PASSWORD,
	}
	user2Id := uuid.Must(uuid.FromString("00000000-0000-0000-0000-000000000002"))
	p.store[user2Id] = User{
		Id:       user2Id,
		Username: USER2_USERNAME,
		Password: USER2_PASSWORD,
	}
	return p
}

func (s *UsersRepositoryImpl) ExistsById(ctx context.Context, userId uuid.UUID) (bool, error) {
	_, exists := s.store[userId]
	return exists, nil
}

func (s *UsersRepositoryImpl) GetByUsername(ctx context.Context, username string) (*User, error) {
	for _, user := range s.store {
		if user.Username == username {
			return &user, nil
		}
	}
	return nil, ErrNotFound
}

func (s *UsersRepositoryImpl) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	user, exists := s.store[id]
	if !exists {
		return nil, ErrNotFound
	}
	return &user, nil
}
