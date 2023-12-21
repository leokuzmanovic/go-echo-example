package services

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v4"
)

const TOKEN_ISSUER = "example.com"

type TokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type TokensService interface {
	CreateToken(claims *jwt.RegisteredClaims) (string, error)
	GetTokens(ctx context.Context, userId uuid.UUID) (null.String, null.String, error)
	CheckToken(ctx context.Context, tokenString string) (uuid.UUID, bool, error)
}

type TokensServiceImpl struct {
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	tokenRepository models.TokensRepository
	usersRepository models.UsersRepository
}

func NewTokensServiceImpl(encodedPrivateKey, encodedPublicKey string, tokensRepository models.TokensRepository, usersRepository models.UsersRepository) *TokensServiceImpl {
	p := new(TokensServiceImpl)
	p.tokenRepository = tokensRepository
	p.usersRepository = usersRepository

	decodedPrivateKey, err := decodeKey(encodedPrivateKey)
	if err != nil {
		err := errors.New("NewTokensServiceImpl - could not decode private key")
		panic(err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return nil
	}
	p.privateKey = privateKey

	publicKey, err := decodeKey(encodedPublicKey)
	if err != nil {
		err := errors.New("NewTokensServiceImpl - could not decode public key")
		panic(err)
	}

	if err == nil {
		key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
		if err != nil {
			panic(err)
		}
		p.publicKey = key
	}

	return p
}

func (s *TokensServiceImpl) CreateToken(claims *jwt.RegisteredClaims) (string, error) {
	var t *jwt.Token
	if claims == nil {
		t = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{})
	} else {
		t = jwt.NewWithClaims(jwt.SigningMethodRS256, *claims)
	}
	token, err := t.SignedString(s.privateKey)
	return token, errors.Wrap(err, "jwt")
}

func (s *TokensServiceImpl) GetTokens(ctx context.Context, userId uuid.UUID) (null.String, null.String, error) {
	claims, err := s.getClaims(ctx, userId)
	if err != nil {
		return null.String{}, null.String{}, err
	}

	accessToken, err := s.CreateToken(claims)
	if err != nil {
		return null.String{}, null.String{}, errors.Wrap(err, "access token")
	}

	refreshToken, err := s.generateRefreshToken(ctx, userId)
	if err != nil {
		return null.String{}, null.String{}, err
	}

	return null.StringFrom(accessToken), null.StringFrom(refreshToken), nil
}

func (s *TokensServiceImpl) CheckToken(ctx context.Context, tokenString string) (uuid.UUID, bool, error) {
	_, claims, valid, err := s.validateAccessToken(tokenString, TOKEN_ISSUER)
	if err != nil {
		return uuid.UUID{}, false, nil
	}
	if !valid {
		return uuid.UUID{}, false, nil
	}

	return s.checkClaims(ctx, claims)
}

func (s *TokensServiceImpl) validateAccessToken(tokenString, tokenIssuer string) (*jwt.Token, *jwt.RegisteredClaims, bool, error) {
	claims := &jwt.RegisteredClaims{}
	var token *jwt.Token

	token, claims, err := s.parseAccessToken(tokenString)

	if err != nil {
		return token, claims, false, err
	}

	if !token.Valid {
		return token, claims, false, nil
	}

	if claims.Issuer != tokenIssuer {
		return token, claims, false, nil
	}

	return token, claims, true, err
}

func (s *TokensServiceImpl) parseAccessToken(tokenString string) (*jwt.Token, *jwt.RegisteredClaims, error) {
	var token *jwt.Token
	token, claims, err := parseJwtTokenRS256(tokenString, s.publicKey)
	return token, claims, err
}

func parseJwtTokenRS256(token string, publicKey *rsa.PublicKey) (*jwt.Token, *jwt.RegisteredClaims, error) {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return parsedToken, nil, err
	} else if !parsedToken.Valid {
		return parsedToken, nil, fmt.Errorf("parser: invalid token")
	} else {
		cls, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			return parsedToken, nil, fmt.Errorf("parser: could not parse claims")
		}
		claims := mapClaims(&cls)
		return parsedToken, claims, nil
	}
}

// NOTE: messy parsing logic but we have tests to cover it
func mapClaims(jwtClaims *jwt.MapClaims) *jwt.RegisteredClaims {
	if jwtClaims == nil {
		return nil
	}

	registeredClaims := jwt.RegisteredClaims{}
	if _, ok := (*jwtClaims)["sub"]; ok {
		if subject, converted := (*jwtClaims)["sub"].(string); converted {
			registeredClaims.Subject = subject
		}
	} else {
		fmt.Println("mapClaims - sub claim not found")
	}
	if _, ok := (*jwtClaims)["iss"]; ok {
		if issuer, converted := (*jwtClaims)["iss"].(string); converted {
			registeredClaims.Issuer = issuer
		} else {
			fmt.Println("mapClaims - iss claim could not be converted")
		}
	} else {
		fmt.Println("mapClaims - iss claim not found")
	}
	//TODO: check aud, exp, iat

	return &registeredClaims
}

func getTokenHeader(tokenString string) (*TokenHeader, error) {
	// token => base64UrlEncode(header) + "." + base64UrlEncode(payload) + "." + signature
	tokenParts := strings.Split(tokenString, ".")
	if len(tokenParts) < 1 {
		return nil, errors.New(fmt.Sprintf("token lenght: %d", len(tokenParts)))
	}

	decodedTokenHeader, err := base64.StdEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode token header")
	}

	var tokenHeader TokenHeader
	err = json.Unmarshal(decodedTokenHeader, &tokenHeader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal token header")
	}

	if tokenHeader.Alg == "" {
		return nil, errors.New("token header alg is empty")
	}

	return &tokenHeader, nil
}

func (s *TokensServiceImpl) checkClaims(ctx context.Context, claims *jwt.RegisteredClaims) (uuid.UUID, bool, error) {
	userId, err := uuid.FromString(claims.Subject)
	if err != nil {
		return uuid.UUID{}, false, errors.Wrap(err, "auth")
	}

	exists, err := s.usersRepository.ExistsById(ctx, userId)
	if err != nil {
		return uuid.UUID{}, false, errors.Wrap(err, "auth")
	}
	if !exists {
		return uuid.UUID{}, false, nil
	}

	return userId, true, nil
}

func (s *TokensServiceImpl) generateRefreshToken(ctx context.Context, userId uuid.UUID) (string, error) {
	id := uniuri.NewLen(50)
	code := uniuri.NewLen(72)
	codeHashed, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, "bcrypt")
	}
	err = s.tokenRepository.Create(ctx, id, string(codeHashed), userId)
	return id + "-" + code, errors.Wrap(err, "db")
}

func (s *TokensServiceImpl) getClaims(ctx context.Context, userId uuid.UUID) (*jwt.RegisteredClaims, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userId.String(),
		Issuer:    TOKEN_ISSUER,
		Audience:  []string{"*.example.com", "example.com", "example"},
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(30 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
	}
	return &claims, nil
}

func decodeKey(encodedKey string) ([]byte, error) {
	key := make([]byte, 0)
	var err error

	if encodedKey == "" {
		err = errors.New("decodeKey - encodedKey is empty")
		return key, err
	}
	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		err = errors.New("decodeKey - failed to decode key")
		return key, err
	}
	return decodedKey, nil
}
