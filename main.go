package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/dgrijalva/jwt-go"
	proto "github.com/logeshwarann-dev/auth-service/proto"
	"google.golang.org/grpc"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	port          = ":50051"
	secretKey     = "bit$PIl@ni2023" // Replace with your actual secret key
	tokenExpiry   = time.Hour * 24   // Token expiry duration
	maxRetries    = 10
	retryInterval = 5 * time.Second
)

type AuthServiceServer struct {
	proto.UnimplementedAuthServiceServer
	db *gorm.DB
}

type User struct {
	ID       int    `gorm:"primaryKey"`
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

func (s *AuthServiceServer) Register(ctx context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {
	user := User{Username: req.Username, Password: req.Password}
	if err := s.db.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to register user: %v", err)
	}
	return &proto.RegisterResponse{UserId: int32(user.ID)}, nil
}

func (s *AuthServiceServer) Login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	var user User
	if err := s.db.Where("username = ? AND password = ?", req.Username, req.Password).First(&user).Error; err != nil {
		return nil, fmt.Errorf("invalid username or password: %v", err)
	}

	token, err := generateToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %v", err)
	}

	return &proto.LoginResponse{Token: token}, nil
}

func generateToken(userID int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(tokenExpiry).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func main() {
	var db *gorm.DB
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// PostgreSQL connection
	for i := 0; i < maxRetries; i++ {
		db, err = gorm.Open(postgres.Open("host=postgres user=postgres password=postgres dbname=auth_db port=5432 sslmode=disable"), &gorm.Config{})
		if err == nil {
			break
		}
		log.Printf("PostgreSQL not ready, retrying in %s... (%d/%d)", retryInterval, i+1, maxRetries)
		time.Sleep(retryInterval)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	proto.RegisterAuthServiceServer(grpcServer, &AuthServiceServer{db: db})

	log.Printf("Auth service listening on %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
