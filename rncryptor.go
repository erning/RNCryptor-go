package rncryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

type RNCryptor interface {
	Decrypt(password string, data []byte) ([]byte, error)
	Encrypt(password string, data []byte) ([]byte, error)

	DecryptWithKey(decKey, hmacKey, data []byte) ([]byte, error)
	EncryptWithKey(encKey, hmacKey, data []byte) ([]byte, error)

	EncryptWithOptions(password string, data, encSalt, hmacSalt, iv []byte) ([]byte, error)
	EncryptWithKeyAndIv(encKey, hmacKey, iv, data []byte) ([]byte, error)
}

type rncryptor struct {
	pbkdfIterations int
}

const (
	blockSize          = 16
	supportedVersion   = byte(3)
	optionUsesPassword = byte(1)
	hmacLength         = 32
	saltLength         = 8
	pbkdfIterations    = 10000
	keyByteLength      = 32
)

var r RNCryptor

func init() {
	r = New()
}

func New() RNCryptor {
	return &rncryptor{
		pbkdfIterations: pbkdfIterations,
	}
}

func (r *rncryptor) SetPBKDFInterations(v int) {
	r.pbkdfIterations = v
}

func Decrypt(password string, data []byte) ([]byte, error) {
	return r.Decrypt(password, data)
}

func (r *rncryptor) Decrypt(password string, data []byte) ([]byte, error) {
	version := data[0]

	if version != supportedVersion {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	options := data[1]
	if options&optionUsesPassword == 0 {
		return nil, fmt.Errorf("cannot decrypt key-based encryption with password")
	}

	encSalt := data[2:10]
	hmacSalt := data[10:18]
	iv := data[18:34]
	cipherText := data[34:(len(data) - hmacLength)]
	expectedHmac := data[len(data)-hmacLength:]

	hmacKey := pbkdf2.Key([]byte(password), hmacSalt, r.pbkdfIterations, keyByteLength, sha1.New)
	testHmac := hmac.New(sha256.New, hmacKey)
	testHmac.Write(data[:len(data)-hmacLength])
	testHmacVal := testHmac.Sum(nil)

	// its important to use hmac.Equal to not leak time
	// information. See https://github.com/RNCryptor/RNCryptor-Spec
	verified := hmac.Equal(testHmacVal, expectedHmac)

	if !verified {
		return nil, fmt.Errorf("password may be incorrect, or the data has been corrupted: (HMAC could not be verified)")
	}

	cipherKey := pbkdf2.Key([]byte(password), encSalt, r.pbkdfIterations, keyByteLength, sha1.New)
	cipherBlock, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(cipherText))
	copy(decrypted, cipherText)
	decrypter := cipher.NewCBCDecrypter(cipherBlock, iv)
	decrypter.CryptBlocks(decrypted, decrypted)

	// un-padd decrypted data
	length := len(decrypted)
	unpadding := int(decrypted[length-1])

	return decrypted[:(length - unpadding)], nil
}

func DecryptWithKey(decKey, hmacKey, data []byte) ([]byte, error) {
	return r.DecryptWithKey(decKey, hmacKey, data)
}

func (r *rncryptor) DecryptWithKey(decKey, hmacKey, data []byte) ([]byte, error) {
	version := data[0]

	if version != supportedVersion {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	options := data[1]
	if options&optionUsesPassword != 0 {
		return nil, fmt.Errorf("cannot decrypt password-encrypted data with key")
	}

	iv := data[2:18]
	cipherText := data[18 : len(data)-hmacLength]
	expectedHmac := data[len(data)-hmacLength:]

	testHmac := hmac.New(sha256.New, hmacKey)
	testHmac.Write(data[:len(data)-32])
	testHmacVal := testHmac.Sum(nil)

	// its important to use hmac.Equal to not leak time
	// information. See https://github.com/RNCryptor/RNCryptor-Spec
	verified := hmac.Equal(testHmacVal, expectedHmac)

	if !verified {
		return nil, fmt.Errorf("key may be incorrect, or the data has been corrupted: (HMAC could not be verified)")
	}

	cipherBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(cipherText))
	copy(decrypted, cipherText)
	decrypter := cipher.NewCBCDecrypter(cipherBlock, iv)
	decrypter.CryptBlocks(decrypted, decrypted)

	// un-padd decrypted data
	length := len(decrypted)
	unpadding := int(decrypted[length-1])

	return decrypted[:(length - unpadding)], nil
}

func Encrypt(password string, data []byte) ([]byte, error) {
	return r.Encrypt(password, data)
}

func (r *rncryptor) Encrypt(password string, data []byte) ([]byte, error) {
	encSalt, encSaltErr := RandBytes(saltLength)
	if encSaltErr != nil {
		return nil, encSaltErr
	}

	hmacSalt, hmacSaltErr := RandBytes(saltLength)
	if hmacSaltErr != nil {
		return nil, hmacSaltErr
	}

	iv, ivErr := RandBytes(blockSize)
	if ivErr != nil {
		return nil, ivErr
	}

	encrypted, encErr := r.EncryptWithOptions(password, data, encSalt, hmacSalt, iv)
	if encErr != nil {
		return nil, encErr
	}
	return encrypted, nil
}

func EncryptWithOptions(password string, data, encSalt, hmacSalt, iv []byte) ([]byte, error) {
	return r.EncryptWithOptions(password, data, encSalt, hmacSalt, iv)
}

func (r *rncryptor) EncryptWithOptions(password string, data, encSalt, hmacSalt, iv []byte) ([]byte, error) {
	if len(password) < 1 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	encKey := pbkdf2.Key([]byte(password), encSalt, r.pbkdfIterations, keyByteLength, sha1.New)
	hmacKey := pbkdf2.Key([]byte(password), hmacSalt, r.pbkdfIterations, keyByteLength, sha1.New)

	version := supportedVersion
	options := optionUsesPassword

	msg := make([]byte, 0)
	msg = append(msg, version)
	msg = append(msg, options)
	msg = append(msg, encSalt...)
	msg = append(msg, hmacSalt...)
	msg = append(msg, iv...)

	ciphertext, hmacValue, err := r.encryptAndHmac(msg, data, iv, encKey, hmacKey)
	if err != nil {
		return nil, err
	}

	msg = append(msg, ciphertext...)
	msg = append(msg, hmacValue...)
	return msg, nil
}

func EncryptWithKey(encKey, hmacKey, data []byte) ([]byte, error) {
	return r.EncryptWithKey(encKey, hmacKey, data)
}

func (r *rncryptor) EncryptWithKey(encKey, hmacKey, data []byte) ([]byte, error) {
	iv, err := RandBytes(blockSize)
	if err != nil {
		return nil, err
	}

	return r.EncryptWithKeyAndIv(encKey, hmacKey, iv, data)
}

func EncryptWithKeyAndIv(encKey, hmacKey, iv, data []byte) ([]byte, error) {
	return r.EncryptWithKeyAndIv(encKey, hmacKey, iv, data)
}

func (r *rncryptor) EncryptWithKeyAndIv(encKey, hmacKey, iv, data []byte) ([]byte, error) {

	version := supportedVersion
	options := byte(0)

	msg := make([]byte, 0)
	msg = append(msg, version)
	msg = append(msg, options)
	msg = append(msg, iv...)

	ciphertext, hmacValue, err := r.encryptAndHmac(msg, data, iv, encKey, hmacKey)
	if err != nil {
		return nil, err
	}

	msg = append(msg, ciphertext...)
	msg = append(msg, hmacValue...)
	return msg, nil
}

func (r *rncryptor) encryptAndHmac(header, data, iv, encKey, hmacKey []byte) ([]byte, []byte, error) {
	cipherBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, err
	}

	// pad text for encryption
	cipherText := make([]byte, len(data))
	copy(cipherText, data)

	padding := blockSize - (len(cipherText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	cipherText = append(cipherText, padText...)

	encrypter := cipher.NewCBCEncrypter(cipherBlock, iv)
	encrypter.CryptBlocks(cipherText, cipherText)

	msg := append(header, cipherText...)

	hmacSrc := hmac.New(sha256.New, hmacKey)
	hmacSrc.Write(msg)
	hmacVal := hmacSrc.Sum(nil)

	return cipherText, hmacVal, nil
}

func RandBytes(num int64) ([]byte, error) {
	bits := make([]byte, num)
	_, err := rand.Read(bits)
	if err != nil {
		return nil, err
	}
	return bits, nil
}
