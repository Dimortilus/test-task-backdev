package database

import (
	"context"
	"errors"

	"github.com/Dimortilus/test-task-backdev/internal/env"
	"github.com/Dimortilus/test-task-backdev/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

const rthCollectionName = "refreshTokensHashed"

// DBupsertRTHdoc добавляет/обновляет документ, хранящий GUID пользователя,
// хеш Refresh токена (конвертирован в string) и его "exp" (expirtaion time),
// а также хеш base64rawURL-раскодированной сигнатуры Access токена (также конвертирован в string) в Mongo.
// "RTH" расшифровывается как "Refresh Token Hash"
func DBupsertRTHdoc(GUID, RTH string, RTexp int64, ATSH string) error {

	guidRTHCollection := Client.Database(env.DB_NAME).Collection(rthCollectionName)
	filter := bson.D{{"GUID", GUID}}
	update := bson.D{
		{
			"$set",
			bson.D{{"RTH", RTH}, {"RTexp", RTexp}, {"ATSH", ATSH}},
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err := guidRTHCollection.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		return errors.New("error upserting RTH document: " + err.Error())
	}

	return nil
}

// DBfindRTHdoc ищет в Mongo по GUID документ где лежит bcrypt хеш Refresh токена, его "exp",
// и хеш сигнатуры Access токена.
// Демаршализирует документ в структуру models.RTHdoc
func DBfindRTHdoc(GUID string) (models.RTHdoc, error) {

	var result models.RTHdoc

	rthCollection := Client.Database(env.DB_NAME).Collection(rthCollectionName)
	filter := bson.D{{"GUID", GUID}}
	if err := rthCollection.FindOne(context.TODO(), filter).Decode(&result); err != nil {
		return models.RTHdoc{}, errors.New("error finding RTH document: " + err.Error())
	}

	return result, nil
}
