package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/Dimortilus/test-task-backdev/internal/database"
	"github.com/Dimortilus/test-task-backdev/internal/env"
	"github.com/Dimortilus/test-task-backdev/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// 15 минут
const accessTokenAge int64 = 60 * 15

// 2 недели
const refreshTokenAge int64 = 60 * 60 * 24 * 7 * 2

type RefreshToken struct {
	Token []byte
	Exp   int64
}

// GenerateRandomBytes генерирует последовательность из n байт, криптографически стойким образом
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// generateAccessToken генерирует JWT Access токен
func generateAccessToken(key []byte, guid string, tokenAge int64) (string, error) {

	if guid == "" {
		err := errors.New("no guid in parameters")
		return "", err
	}

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(tokenAge))),
		Subject:   guid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(key)

}

// generateRefreshToken генерирует Refresh токен, который преставляет собой
// случайную последовательность из 32 байт.
func generateRefreshToken(tokenAge int64) (RefreshToken, error) {
	var (
		refreshToken RefreshToken
		randomBytes  []byte
		err          error
	)

	if randomBytes, err = generateRandomBytes(32); err != nil {
		return refreshToken, err
	}

	refreshToken = RefreshToken{
		Token: randomBytes,
		Exp:   time.Now().Add(time.Second * time.Duration(tokenAge)).Unix(),
	}

	return refreshToken, err
}

// generateTokens генерирует пару: Access токен, Refresh токен
func generateTokens(GUID string) (string, RefreshToken, error) {
	var (
		accessTokenStr       string
		accessTokenSignature []byte
		refreshToken         RefreshToken
		atsh                 []byte
		rth                  []byte
		err                  error
	)

	// Генерация Access токена
	if accessTokenStr, err = generateAccessToken([]byte(env.ACCESS_TOKEN_SECRET), GUID, accessTokenAge); err != nil {
		return "", RefreshToken{}, errors.New("error generating accessToken: " + err.Error())
	}

	// Извлечение сигнатуры Access токена, раскодирование из base64rawURL
	if accessTokenSignature, err = extractJWTSignatureDecodeB64rawURL(accessTokenStr); err != nil {
		return "", RefreshToken{}, errors.New("error extracting accessToken signature: " + err.Error())
	}

	// Хеширование base64rawURL-раскодированной сигнатуры Access токена
	if atsh, err = bcrypt.GenerateFromPassword(accessTokenSignature, bcrypt.DefaultCost); err != nil {
		return "", RefreshToken{}, errors.New("error hashing accessToken signature: " + err.Error())
	}

	// Генерация Refresh токена
	if refreshToken, err = generateRefreshToken(refreshTokenAge); err != nil {
		return "", RefreshToken{}, errors.New("error generating refreshToken: " + err.Error())
	}

	// Хеширование Refresh токена
	if rth, err = bcrypt.GenerateFromPassword(refreshToken.Token, bcrypt.DefaultCost); err != nil {
		return "", RefreshToken{}, errors.New("error hashing refreshToken: " + err.Error())
	}

	// Запись хеша и expiration date Refresh токена,
	// а также хеша base64rawURL-раскодированной сигнатуры Access токена в Mongo
	if err = database.DBupsertRTHdoc(GUID, string(rth), refreshToken.Exp, string(atsh)); err != nil {
		return "", RefreshToken{}, errors.New("error upserting hashed refreshToken: " + err.Error())
	}

	return accessTokenStr, refreshToken, err
}

// extractJWTSignatureDecodeB64rawURL извлекает сигнатуру Access токена, раскодирует из base64rawURL
func extractJWTSignatureDecodeB64rawURL(accessTokenStr string) ([]byte, error) {
	var (
		bytesWritten int
		err          error
	)

	accessTokenSignature := make([]byte, 64)

	accessTokenSignatureB64 := bytes.Split([]byte(accessTokenStr), []byte("."))[2]
	bytesWritten, err = base64.RawURLEncoding.Decode(accessTokenSignature, accessTokenSignatureB64)

	if bytesWritten == 0 {
		return nil, errors.New("error base64url-decoding signature, empty sequence")
	}

	if err != nil {
		return nil, err
	}

	return accessTokenSignature, err
}

// setCookies создаёт cookies. Refresh токен предварительно кодируется в base64
func setCookies(c *gin.Context, accessTokenStr string, refreshToken RefreshToken) {
	c.SetCookie("ttb_access_token", accessTokenStr, int(accessTokenAge), "/", "localhost", false, true)
	// Кодирование Refresh токена в base64 перед записью в cookie
	refreshTokenB64str := base64.StdEncoding.EncodeToString(refreshToken.Token)
	c.SetCookie("ttb_refresh_token", refreshTokenB64str, int(refreshTokenAge), "/refresh-tokens", "localhost", false, true)
}

// getCookies Извлечение Refresh токена в виде base64 строки из cookies.
// Раскодирование из base64 в исходные байты
func getRefreshTokenBytesFromCookie(c *gin.Context) ([]byte, error) {

	var (
		refreshTokenB64str string
		refreshTokenBytes  []byte
		err                error
	)

	if refreshTokenB64str, err = c.Cookie("ttb_refresh_token"); err != nil {
		return nil, errors.New(err.Error() + " (ttb_refresh_token)")
	}

	if refreshTokenBytes, err = base64.StdEncoding.DecodeString(refreshTokenB64str); err != nil {
		return nil, errors.New(err.Error() + " (ttb_refresh_token)")
	}

	return refreshTokenBytes, err

}

// validateTokensViaDB ищет в Mongo по GUID документ, где лежит bcrypt хеш Refresh токена, его "exp",
// и хеш сигнатуры Access токена.
// Проверяет Refresh токен на соответствие с помощью его хеша.
// Проверяет не истек ли срок годности Refresh токена.
// Проверяет base64rawURL-раскодированную сигнатуру Access токена на соответствие с помощью её хеша.
func validateTokensViaDB(GUID string, refreshTokenBytes []byte, accessTokenStr string) error {
	var (
		rthDoc               models.RTHdoc
		accessTokenSignature []byte
		err                  error
	)
	// Поиск документа в Mongo и демаршализация в структуру models.RTHdoc
	if rthDoc, err = database.DBfindRTHdoc(GUID); err != nil {
		return errors.New("error finding RTH document: " + err.Error())
	}

	// Извлечение сигнатуры Access токена, раскодирование из base64rawURL
	if accessTokenSignature, err = extractJWTSignatureDecodeB64rawURL(accessTokenStr); err != nil {
		return errors.New("error extracting Access token signature: " + err.Error())
	}

	// Проверка соответствия сигнатуры Access токена его хешу
	if err = bcrypt.CompareHashAndPassword([]byte(rthDoc.ATSH), accessTokenSignature); err != nil {
		return errors.New("error comparing Access token to hash: " + err.Error())
	}

	// Проверка соответствия Refresh токена его хешу
	if err = bcrypt.CompareHashAndPassword([]byte(rthDoc.RTH), refreshTokenBytes); err != nil {
		return errors.New("error comparing Refresh token to hash: " + err.Error())
	}

	// Проверка Refresh токена на истечение срока годности
	if time.Now().Compare(time.Unix(rthDoc.RTexp, 0)) > 0 {
		return errors.New("error checking Refresh token expiration time: token expired")
	}

	return nil
}

// parseValidateAccessToken выполняет парсинг и валидацию сигнатуры токена
func parseValidateAccessToken(jwtToken, key string) (*jwt.Token, error) {

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, OK := token.Method.(*jwt.SigningMethodHMAC); !OK {
			return nil, errors.New("bad jwt token signing method")
		}
		return []byte(key), nil
	})

	if err != nil {
		return nil, errors.New("bad jwt token: " + err.Error())
	}

	return token, nil
}

// GenerateTokensHandler обрабатывает POST запрос.
// GUID пользователя в JSON
func GenerateTokensHandler(c *gin.Context) {

	var (
		newAccessTokenStr string
		newRefreshToken   RefreshToken
		err               error
	)

	user := models.User{}

	// Сериализация JSON запроса через BindJSON в структуру типа User
	if err := c.BindJSON(&user); err != nil {
		errStr := "error getting GUID from req JSON: "
		slog.Error(errStr + err.Error())
		c.JSON(401, errStr)
		return
	}

	// Генерация Access и Refresh токенов
	if newAccessTokenStr, newRefreshToken, err = generateTokens(user.GUID); err != nil {
		errStr := "error generating tokens: "
		slog.Error(errStr + err.Error())
		c.JSON(401, errStr)
		return
	}

	// Создание cookies. Refresh токен предварительно кодируется в base64
	setCookies(c, newAccessTokenStr, newRefreshToken)
	successStr := "tokens generated successfully"
	c.JSON(200, successStr)
	slog.Info(successStr)

}

// RefreshTokensHandler обрабатывает POST запрос на создание новой пары Access-Refresh токенов.
// GUID пользователя в JSON.
// Текущие Refresh и Access токены хранятся в cookies.
func RefreshTokensHandler(c *gin.Context) {
	var (
		accessTokenStr    string
		refreshTokenBytes []byte
		newAccessTokenStr string
		newRefreshToken   RefreshToken
		err               error
	)

	user := models.User{}

	// Сериализация JSON запроса через BindJSON в структуру типа User, полем которой является GUID
	if err := c.BindJSON(&user); err != nil {
		errStr := "error getting GUID from req JSON: " + err.Error()
		c.JSON(401, errStr)
		slog.Error(errStr)
		return
	}

	// Извлечение Access токена в виде строки из cookies.
	if accessTokenStr, err = c.Cookie("ttb_access_token"); err != nil {
		errStr := "error getting Access Token from cookie: " + err.Error() + " (ttb_access_token)"
		c.JSON(401, errStr)
		slog.Error(errStr)
		return
	}

	// Валидация Access токена (подпись, срок годности)
	if _, err = parseValidateAccessToken(accessTokenStr, env.ACCESS_TOKEN_SECRET); err != nil {
		errStr := "error parsing and validating Access token: " + err.Error()
		c.JSON(401, errStr)
		slog.Error(errStr)
		return
	}

	// Извлечение Refresh токена в виде base64-строки из cookies. Раскодирование из base64 в исходные байты
	if refreshTokenBytes, err = getRefreshTokenBytesFromCookie(c); err != nil {
		errStr := "error getting Refresh Token from cookie: " + err.Error()
		c.JSON(401, errStr)
		slog.Error(errStr)
		return
	}

	// Поиск в Mongo по GUID документа, где лежит bcrypt хеш Refresh токена, его "exp",
	// и хеш сигнатуры Access токена.
	// Проверка Refresh токен на соответствие с помощью его хеша.
	// Проверка не истек ли срок годности токена.
	// Проверка base64rawURL-раскодированной сигнатуры Access токена на соответствие с помощью её хеша.
	if err = validateTokensViaDB(user.GUID, refreshTokenBytes, accessTokenStr); err != nil {
		errStr := "error validating tokens via DB: " + err.Error()
		c.JSON(401, errStr)
		slog.Error(errStr)
		return
	}

	// Генерация Access и Refresh токенов
	if newAccessTokenStr, newRefreshToken, err = generateTokens(user.GUID); err != nil {
		errStr := "error generating tokens: "
		slog.Error(errStr + err.Error())
		c.JSON(401, errStr)
		return
	}

	// Создание cookies. Refresh токен предварительно кодируется в base64
	setCookies(c, newAccessTokenStr, newRefreshToken)
	successStr := "tokens refreshed successfully"
	c.JSON(200, successStr)
	slog.Info(successStr)
}

// ReplaceTokenCookieHandler обрабатывает POST запрос,
// выполняя в cookie подмену текущего Access или Refresh токена на переданный в JSON запроса.
// Поле JSON запроса для токена, который требуется оставить прежним, заполнено пустой строкой.
// Используется для тестирования связности Access и Refresh токенов во время Refresh операции.
func ReplaceTokenCookieHandler(c *gin.Context) {

	tokenName := ""
	tokensReplacement := models.TokensReplacement{}

	// Сериализация JSON запроса через BindJSON в структуру типа User
	if err := c.BindJSON(&tokensReplacement); err != nil {
		errStr := "error getting fields from req JSON: "
		slog.Error(errStr + err.Error())
		c.JSON(401, errStr)
		return
	}

	// Подмена cookie Access токена
	if len(tokensReplacement.AccessToken) != 0 {
		c.SetCookie("ttb_access_token", tokensReplacement.AccessToken, int(accessTokenAge), "/", "localhost", false, true)
		tokenName = "Access"
	}

	// Подмена cookie Refresh токена
	if len(tokensReplacement.RefreshToken) != 0 {
		c.SetCookie("ttb_refresh_token", tokensReplacement.RefreshToken, int(accessTokenAge), "/refresh-tokens", "localhost", false, true)
		tokenName = "Refresh"
	}

	if len(tokenName) == 0 {
		successStr := "no token cookie was requested to be replaced"
		c.JSON(304, successStr)
		slog.Info(successStr)
		return
	}

	successStr := tokenName + " token cookie replaced successfully"
	c.JSON(200, successStr)
	slog.Info(successStr)
}

// TestAccessTokenHandler обрабатывает тестовые POST запросы с Access токеном
func TestAccessTokenHandler(c *gin.Context) {

	var (
		accessTokenStr string
		accesshToken   *jwt.Token
		err            error
	)

	// Извлечение Access токена в виде строки из cookies.
	if accessTokenStr, err = c.Cookie("ttb_access_token"); err != nil {
		errStr := err.Error() + " (ttb_access_token)"
		c.JSON(401, errStr)
		slog.Error(errStr)
		return
	}

	// Валидация Access токена (подпись, срок годности)
	if accesshToken, err = parseValidateAccessToken(accessTokenStr, env.ACCESS_TOKEN_SECRET); err != nil {
		errStr := "error parsing and validating Access token: " + err.Error()
		c.JSON(401, errStr)
		slog.Error(errStr)
		return
	}

	_ = accesshToken

	successStr := "access token tested successfully"
	c.JSON(200, successStr)
	slog.Info(successStr)
}
