package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/Dimortilus/test-task-backdev/internal/auth"
	"github.com/Dimortilus/test-task-backdev/internal/database"
	"github.com/Dimortilus/test-task-backdev/internal/env"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {

	var (
		envVarPresent bool
		err           error
	)

	// Загрузка secrets из .env файла в глобальные переменные
	if err := godotenv.Load("./internal/env/.env"); err != nil {
		slog.Error("error loading .env file")
		return
	}

	env.ACCESS_TOKEN_SECRET, envVarPresent = os.LookupEnv("ACCESS_TOKEN_SECRET")
	if !envVarPresent {
		slog.Error("error: enironment variable ACCESS_TOKEN_SECRET not present in .env file")
		return
	} else if env.ACCESS_TOKEN_SECRET == "" {
		slog.Error("error: enironment variable ACCESS_TOKEN_SECRET is empty")
		return
	}

	// Подключение к MongoDB
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	database.Client, err = mongo.Connect(context.TODO(), clientOptions)

	if err != nil {
		slog.Error(err.Error())
	}

	// Проверка соединения
	err = database.Client.Ping(context.TODO(), nil)

	if err != nil {
		slog.Error(err.Error())
	}

	env.DB_NAME = os.Getenv("DB_NAME")

	slog.Info("Connected to MongoDB!")

	router := gin.Default()
	router.POST("/generate-tokens", auth.GenerateTokensHandler)
	router.POST("/refresh-tokens", auth.RefreshTokensHandler)
	router.POST("/replace-token-cookie", auth.ReplaceTokenCookieHandler)
	router.POST("/test-access-token", auth.TestAccessTokenHandler)
	router.Run("localhost:8080")
}
