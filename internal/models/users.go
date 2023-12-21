package models

import (
	"context"

	"github.com/gofrs/uuid"
)

type User struct {
	Id       uuid.UUID
	Username string
	Password string
}

type UsersRepository interface {
	ExistsById(ctx context.Context, userId uuid.UUID) (bool, error)
	Get(ctx context.Context, id uuid.UUID) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	/*
		Create(ctx context.Context, tx *sql.Tx, email, username null.String, countryCode string, isEmailVerified bool,
			hashedPassword null.String, interfaceLanguageCode string, googleID null.String, appleID null.String) (uuid.NullUUID, error)

		ExistsByEmail(ctx context.Context, email string) (bool, error)
		ExistsByUsername(ctx context.Context, username string) (bool, error)
		GetRoles(ctx context.Context, accountUUID uuid.UUID) ([]string, error)
		ExistsByGoogleID(ctx context.Context, googleID string) (bool, error)
		ExistsByAppleID(ctx context.Context, appleID string) (bool, error)
		GetByEmailAuth(ctx context.Context, email string) (AccountAuth, error)

		GetByGoogleID(ctx context.Context, subject string) (AccountAuth, error)
		GetByAppleID(ctx context.Context, subject string) (AccountAuth, error)
		GetAuthUUID(ctx context.Context, accountUUID uuid.UUID) (AccountAuth, error)
		UpdateUsername(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID, newUsername string) error
		UpdateEmail(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID, newEmail string) error
		GetAccountByUUID(ctx context.Context, accountUUID uuid.UUID) (Account, error)
		UpdatePassword(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID, password []byte) error
		GetByEmail(ctx context.Context, email string) (Account, error)
		SetActive(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID) error
		Delete(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID) error
		UpdateDataCenterRegion(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID, dcRegion string) error
		GetAccountDataCenters(ctx context.Context, accountUUID uuid.UUID) ([]string, error)
		GetAccountsForAnonymizationOlderThan(ctx context.Context, oldestDeletedOn time.Time) ([]uuid.UUID, error)
		AnonymizeAccount(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID) error
		GetAccounts(ctx context.Context, limit int, offset int) ([]Account, error)
	*/
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
		Username: "user1",
		Password: "pass1",
	}
	user2Id := uuid.Must(uuid.FromString("00000000-0000-0000-0000-000000000002"))
	p.store[user2Id] = User{
		Id:       user2Id,
		Username: "user2",
		Password: "pass2",
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

/*
func (s *UsersRepositoryImpl) GetAccounts(ctx context.Context, limit, offset int) ([]Account, error) {
	var accounts []Account
	err := database.Select(ctx, s.dbro, &accounts, `SELECT {C} FROM public.account order by public.account.uuid asc LIMIT $1 OFFSET $2`, limit, offset)
	return accounts, errors.Wrap(err, "db")
}

func (s *UsersRepositoryImpl) Create(ctx context.Context, tx *sql.Tx, email, username null.String, countryCode string, isEmailVerified bool,
	hashedPassword null.String, interfaceLanguageCode string, googleID null.String, appleID null.String) (uuid.NullUUID, error) {
	var accountUUID uuid.NullUUID

	err := tx.QueryRowContext(ctx, `INSERT INTO account (is_email_confirmed, email, username, interface_language_code, country_code) VALUES ($1, $2, $3, $4, $5) RETURNING uuid`,
		isEmailVerified, email, username, interfaceLanguageCode, countryCode).Scan(&accountUUID)
	if err != nil {
		return accountUUID, errors.Wrap(err, "db")
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO account_secret (account_uuid, password, google_id, apple_id) VALUES ($1, $2, $3, $4)`,
		accountUUID, hashedPassword, googleID, appleID)
	if err != nil {
		return accountUUID, errors.Wrap(err, "db")
	}

	return accountUUID, errors.Wrap(err, "db")
}



func (s *UsersRepositoryImpl) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := s.dbro.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account WHERE email = $1)`, email).Scan(&exists)
	return exists, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	var exists bool
	err := s.dbro.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account WHERE username = $1)`, username).Scan(&exists)
	return exists, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) GetRoles(ctx context.Context, accountUUID uuid.UUID) ([]string, error) {
	roles := []string{}
	rows, err := s.dbro.QueryContext(ctx, "SELECT role FROM account_roles WHERE account_uuid = $1 ", accountUUID)
	if err != nil {
		return roles, errors.Wrap(err, "db")
	}
	if rows.Err() != nil {
		return roles, errors.Wrap(rows.Err(), "db")
	}
	defer rows.Close()

	for rows.Next() {
		var roleName string
		err = rows.Scan(&roleName)
		if err != nil {
			return roles, errors.Wrap(err, "db")
		}
		roles = append(roles, roleName)
	}

	return roles, nil
}

func (s *AccountRepositoryImpl) ExistsByGoogleID(ctx context.Context, googleID string) (bool, error) {
	var exists bool
	err := s.dbro.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM account_secret WHERE google_id = $1
		)
	`, googleID).Scan(&exists)
	return exists, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) ExistsByAppleID(ctx context.Context, appleID string) (bool, error) {
	var exists bool
	err := s.dbro.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM account_secret WHERE apple_id = $1
		)
	`, appleID).Scan(&exists)
	return exists, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) isDataCenterRegionUsedByAccount(ctx context.Context, accountUUID uuid.UUID, dcRegion string) (bool, error) {
	var exists bool
	err := s.dbro.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM account_data_centers WHERE account_uuid = $1 AND data_center_region = $2
		)
	`, accountUUID, dcRegion).Scan(&exists)
	return exists, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) GetByUsernameAuth(ctx context.Context, username string) (AccountAuth, error) {
	var account AccountAuth
	err := database.Get(ctx, s.dbro, &account, `
		SELECT {C}
		FROM public.account
		JOIN account_secret ON account_secret.account_uuid = public.account.uuid
		WHERE username = $1
	`, username)
	return account, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) GetByEmailAuth(ctx context.Context, email string) (AccountAuth, error) {
	var account AccountAuth
	err := database.Get(ctx, s.dbro, &account, `
		SELECT {C}
		FROM public.account
		JOIN account_secret ON account_secret.account_uuid = public.account.uuid
		WHERE email = $1
	`, email)
	return account, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) GetByGoogleID(ctx context.Context, subject string) (AccountAuth, error) {
	var account AccountAuth
	err := database.Get(ctx, s.dbro, &account, `
		SELECT {C}
		FROM public.account
		JOIN account_secret ON account_secret.account_uuid = public.account.uuid
		WHERE account_secret.google_id = $1
	`, subject)
	return account, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) GetByAppleID(ctx context.Context, subject string) (AccountAuth, error) {
	var account AccountAuth
	err := database.Get(ctx, s.dbro, &account, `
		SELECT {C}
		FROM public.account
		JOIN account_secret ON account_secret.account_uuid = public.account.uuid
		WHERE account_secret.apple_id = $1
	`, subject)
	return account, errors.Wrap(err, "db")
}

func (u *AccountAuth) ScanRow(r database.Row) error {
	return errors.Wrap(r.Scan(&u.UUID, &u.IsEmailConfirmed, &u.Email, &u.Username, &u.Password, &u.InterfaceLanguageCode, &u.TwoFactorAuthenticationIsActivated, &u.TwoFactorAuthenticationSecret, &u.CountryCode), "db")
}

func (s *AccountRepositoryImpl) GetAuthUUID(ctx context.Context, accountUUID uuid.UUID) (AccountAuth, error) {
	var account AccountAuth
	err := database.Get(ctx, s.dbro, &account, `
		SELECT {C}
		FROM public.account
		JOIN account_secret ON account_secret.account_uuid = public.account.uuid
		WHERE uuid = $1
	`, accountUUID)
	return account, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) UpdateUsername(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID, username string) error {
	_, err := tx.ExecContext(ctx, `UPDATE public.account SET username = $2 WHERE uuid = $1`, accountUUID, username)
	return errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) UpdateEmail(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID, email string) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM account_email_confirmation WHERE account_uuid = $1", accountUUID)
	if err != nil {
		return errors.Wrap(err, "db")
	}

	_, err = tx.ExecContext(ctx, `UPDATE public.account SET email = $2, is_email_confirmed = false WHERE uuid = $1`, accountUUID, email)
	return errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) UpdateDataCenterRegion(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID, dcRegion string) error {
	_, err := tx.ExecContext(ctx, `UPDATE public.account SET data_center_region = $2 WHERE uuid = $1`, accountUUID, dcRegion)
	if err != nil {
		return errors.Wrap(err, "db")
	}

	exists, err := s.isDataCenterRegionUsedByAccount(ctx, accountUUID, dcRegion)
	if err != nil {
		return errors.Wrap(err, "db")
	}
	if !exists {
		_, err = tx.ExecContext(ctx, `INSERT INTO account_data_centers (account_uuid, data_center_region) VALUES ($1, $2)`,
			accountUUID, dcRegion)
		if err != nil {
			return errors.Wrap(err, "db")
		}
	}
	return errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) GetAccountDataCenters(ctx context.Context, accountUUID uuid.UUID) ([]string, error) {
	var dcs []string
	rows, err := s.dbro.QueryContext(ctx, `SELECT data_center_region from account_data_centers WHERE account_uuid = $1`, accountUUID)
	if err != nil {
		return dcs, errors.Wrap(err, "db")
	}
	if rows.Err() != nil {
		return dcs, errors.Wrap(rows.Err(), "db")
	}
	defer rows.Close()

	for rows.Next() {
		var dc string
		err = rows.Scan(&dc)
		if err != nil {
			return dcs, errors.Wrap(err, "db")
		}
		dcs = append(dcs, dc)
	}
	return dcs, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) GetAccountsForAnonymizationOlderThan(ctx context.Context, oldestDeletedOn time.Time) ([]uuid.UUID, error) {
	var accountUUIDs []uuid.UUID
	rows, err := s.dbro.QueryContext(ctx, `SELECT uuid FROM _account WHERE deleted_on < $1 and email IS NOT NULL`, oldestDeletedOn)
	if err != nil {
		return accountUUIDs, errors.Wrap(err, "db")
	}
	if rows.Err() != nil {
		return accountUUIDs, errors.Wrap(rows.Err(), "db")
	}
	defer rows.Close()

	for rows.Next() {
		var accountUUID uuid.UUID
		err = rows.Scan(&accountUUID)
		if err != nil {
			return accountUUIDs, errors.Wrap(err, "db")
		}

		accountUUIDs = append(accountUUIDs, accountUUID)
	}
	return accountUUIDs, nil
}

func (s *AccountRepositoryImpl) GetAccountByUUID(ctx context.Context, accountUUID uuid.UUID) (Account, error) {
	var account Account
	err := database.Get(ctx, s.dbro, &account, `
		SELECT {C}
		FROM public.account
		WHERE public.account.uuid = $1
	`, accountUUID)
	return account, errors.Wrap(err, "db")
}

func (u *Account) ScanRow(r database.Row) error {
	return errors.Wrap(r.Scan(&u.UUID, &u.Email, &u.Username, &u.IsEmailConfirmed, &u.InterfaceLanguageCode, &u.DeletedOn), "db")
}

func (s *AccountRepositoryImpl) UpdatePassword(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID, hashedPassword []byte) error {
	_, err := tx.ExecContext(ctx, `UPDATE account_secret SET password = $2 WHERE account_uuid = $1`, accountUUID, hashedPassword)
	return errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) AnonymizeAccount(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `UPDATE _account SET email = NULL, username = NULL WHERE uuid = $1`, accountUUID)
	return errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) GetByEmail(ctx context.Context, email string) (Account, error) {
	var account Account
	err := database.Get(ctx, s.dbro, &account, `
		SELECT {C}
		FROM public.account
		WHERE email = $1
	`, email)
	return account, errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) SetActive(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `UPDATE public.account SET is_email_confirmed = true WHERE uuid = $1`, accountUUID)
	return errors.Wrap(err, "db")
}

func (s *AccountRepositoryImpl) Delete(ctx context.Context, tx *sql.Tx, accountUUID uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `UPDATE _account SET deleted_on = $1 WHERE uuid = $2`, time.Now(), accountUUID)
	return errors.Wrap(err, "db")
}
*/
