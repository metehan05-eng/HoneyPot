package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/metehan05-eng/sentinel-trap/internal/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Store interface {
	Save(event logger.Event) error
	Recent(limit int) ([]logger.Event, error)
}

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if path == "" {
		path = "logs/honeypot.db"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			server TEXT,
			service TEXT NOT NULL,
			remote_ip TEXT,
			payload TEXT,
			username TEXT,
			password TEXT,
			user_agent TEXT
		);`); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Save(event logger.Event) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`
		INSERT INTO events (timestamp, server, service, remote_ip, payload, username, password, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp, event.Server, event.Service, event.RemoteIP, event.Payload, event.Username, event.Password, event.UserAgent,
	)
	return err
}

func (s *SQLiteStore) Recent(limit int) ([]logger.Event, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
		SELECT timestamp, server, service, remote_ip, payload, username, password, user_agent
		FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []logger.Event
	for rows.Next() {
		var event logger.Event
		if err := rows.Scan(&event.Timestamp, &event.Server, &event.Service, &event.RemoteIP, &event.Payload, &event.Username, &event.Password, &event.UserAgent); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

type MongoStore struct {
	collection *mongo.Collection
}

func NewMongoStore(uri, dbName, collectionName string) (*MongoStore, error) {
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}
	if dbName == "" {
		dbName = "honeypot"
	}
	if collectionName == "" {
		collectionName = "honeypot_events"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}

	return &MongoStore{collection: client.Database(dbName).Collection(collectionName)}, nil
}

func (m *MongoStore) Save(event logger.Event) error {
	if m == nil || m.collection == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.collection.InsertOne(ctx, event)
	return err
}

func (m *MongoStore) Recent(limit int) ([]logger.Event, error) {
	if m == nil || m.collection == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetLimit(int64(limit)).SetSort(bson.D{{Key: "_id", Value: -1}})
	cursor, err := m.collection.Find(ctx, bson.D{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []logger.Event
	for cursor.Next(ctx) {
		var event logger.Event
		if err := cursor.Decode(&event); err != nil {
			return nil, err
		}
		results = append(results, event)
	}
	return results, cursor.Err()
}

func (m *MongoStore) Close() error {
	if m == nil {
		return nil
	}
	return nil
}

func Example() {
	fmt.Println("storage package loaded")
}
