package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"code-code.internal/go-contract/domainerror"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const credentialMaterialTableName = "platform_credential_material_values"

// CredentialMaterialStore owns sensitive credential material persistence.
// K8s Secrets are runtime projections only and are not a credential material store.
type CredentialMaterialStore interface {
	ReadValues(ctx context.Context, credentialID string) (map[string]string, error)
	WriteValues(ctx context.Context, credentialID string, values map[string]string) error
	MergeValues(ctx context.Context, credentialID string, values map[string]string) error
	DeleteValues(ctx context.Context, credentialID string) error
}

type EncryptedCredentialValue struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

type CredentialMaterialEncryptor interface {
	Encrypt(plaintext []byte) (EncryptedCredentialValue, error)
	Decrypt(value EncryptedCredentialValue) ([]byte, error)
}

type aesGCMCredentialMaterialEncryptor struct {
	keyID string
	gcm   cipher.AEAD
}

func NewAESGCMCredentialMaterialEncryptor(keyID string, key []byte) (CredentialMaterialEncryptor, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, fmt.Errorf("credentials: credential encryption key id is empty")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("credentials: create credential material cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credentials: create credential material gcm: %w", err)
	}
	return &aesGCMCredentialMaterialEncryptor{keyID: keyID, gcm: gcm}, nil
}

func NewAESGCMCredentialMaterialEncryptorFromBase64(keyID string, encodedKey string) (CredentialMaterialEncryptor, error) {
	encodedKey = strings.TrimSpace(encodedKey)
	if encodedKey == "" {
		return nil, fmt.Errorf("credentials: credential encryption key is empty")
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(encodedKey)
	}
	if err != nil {
		return nil, fmt.Errorf("credentials: decode credential encryption key: %w", err)
	}
	return NewAESGCMCredentialMaterialEncryptor(keyID, key)
}

func (e *aesGCMCredentialMaterialEncryptor) Encrypt(plaintext []byte) (EncryptedCredentialValue, error) {
	if e == nil || e.gcm == nil {
		return EncryptedCredentialValue{}, fmt.Errorf("credentials: credential material encryptor is nil")
	}
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedCredentialValue{}, fmt.Errorf("credentials: generate credential material nonce: %w", err)
	}
	return EncryptedCredentialValue{
		KeyID:      e.keyID,
		Nonce:      nonce,
		Ciphertext: e.gcm.Seal(nil, nonce, plaintext, nil),
	}, nil
}

func (e *aesGCMCredentialMaterialEncryptor) Decrypt(value EncryptedCredentialValue) ([]byte, error) {
	if e == nil || e.gcm == nil {
		return nil, fmt.Errorf("credentials: credential material encryptor is nil")
	}
	if strings.TrimSpace(value.KeyID) != e.keyID {
		return nil, fmt.Errorf("credentials: unsupported credential material key id %q", value.KeyID)
	}
	plaintext, err := e.gcm.Open(nil, value.Nonce, value.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("credentials: decrypt credential material value: %w", err)
	}
	return plaintext, nil
}

type postgresCredentialMaterialStore struct {
	pool      *pgxpool.Pool
	namespace string
	encryptor CredentialMaterialEncryptor
}

func NewPostgresCredentialMaterialStore(
	pool *pgxpool.Pool,
	namespace string,
	encryptor CredentialMaterialEncryptor,
) (CredentialMaterialStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("credentials: postgres material store pool is nil")
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("credentials: postgres material store namespace is empty")
	}
	if encryptor == nil {
		return nil, fmt.Errorf("credentials: postgres material store encryptor is nil")
	}
	return &postgresCredentialMaterialStore{pool: pool, namespace: namespace, encryptor: encryptor}, nil
}

func (s *postgresCredentialMaterialStore) ReadValues(ctx context.Context, credentialID string) (map[string]string, error) {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return nil, domainerror.NewValidation("credentials: credential id is empty")
	}
	rows, err := s.pool.Query(ctx, `
select material_key, key_id, nonce, ciphertext
from platform_credential_material_values
where namespace = $1 and credential_id = $2
order by material_key`, s.namespace, credentialID)
	if err != nil {
		return nil, fmt.Errorf("credentials: read credential material %q: %w", credentialID, err)
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var key string
		var encrypted EncryptedCredentialValue
		if err := rows.Scan(&key, &encrypted.KeyID, &encrypted.Nonce, &encrypted.Ciphertext); err != nil {
			return nil, fmt.Errorf("credentials: scan credential material %q: %w", credentialID, err)
		}
		plaintext, err := s.encryptor.Decrypt(encrypted)
		if err != nil {
			return nil, err
		}
		if key = strings.TrimSpace(key); key != "" {
			values[key] = strings.TrimSpace(string(plaintext))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values, nil
}

func (s *postgresCredentialMaterialStore) WriteValues(ctx context.Context, credentialID string, values map[string]string) error {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return domainerror.NewValidation("credentials: credential id is empty")
	}
	trimmed := trimMaterialValueUpdates(values)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
delete from platform_credential_material_values
where namespace = $1 and credential_id = $2`, s.namespace, credentialID); err != nil {
		return err
	}
	for key, value := range trimmed {
		if err := s.upsertEncryptedValue(ctx, tx, credentialID, key, value); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *postgresCredentialMaterialStore) MergeValues(ctx context.Context, credentialID string, values map[string]string) error {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return domainerror.NewValidation("credentials: credential id is empty")
	}
	trimmed := trimMaterialValueUpdates(values)
	if len(trimmed) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for key, value := range trimmed {
		if err := s.upsertEncryptedValue(ctx, tx, credentialID, key, value); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *postgresCredentialMaterialStore) DeleteValues(ctx context.Context, credentialID string) error {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return domainerror.NewValidation("credentials: credential id is empty")
	}
	_, err := s.pool.Exec(ctx, `
delete from platform_credential_material_values
where namespace = $1 and credential_id = $2`, s.namespace, credentialID)
	return err
}

func (s *postgresCredentialMaterialStore) upsertEncryptedValue(
	ctx context.Context,
	tx pgx.Tx,
	credentialID string,
	materialKey string,
	value string,
) error {
	encrypted, err := s.encryptor.Encrypt([]byte(value))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
insert into platform_credential_material_values (
	namespace,
	credential_id,
	material_key,
	key_id,
	nonce,
	ciphertext,
	created_at,
	updated_at
) values ($1, $2, $3, $4, $5, $6, now(), now())
on conflict (namespace, credential_id, material_key) do update
set key_id = excluded.key_id,
    nonce = excluded.nonce,
    ciphertext = excluded.ciphertext,
    updated_at = now()`,
		s.namespace,
		credentialID,
		materialKey,
		encrypted.KeyID,
		encrypted.Nonce,
		encrypted.Ciphertext,
	)
	return err
}
