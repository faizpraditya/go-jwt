package main

import (
	"fmt"
	"go-jwt/authenticator"
	"go-jwt/delivery/middleware"
	"go-jwt/model"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
)

var ApplicationName = "ENIGMA"
var JwtSigningMethod = jwt.SigningMethodHS256
var JwtSignatureKey = []byte("P@ssw0rd")

func main() {
	r := gin.Default()
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "12345678",
		DB:       0,
	})

	tokenConfig := authenticator.TokenConfig{
		ApplicationName:     "ENIGMA",
		JwtSigningMethod:    jwt.SigningMethodHS256,
		JwtSignatureKey:     "P@ssw0rd",
		AccessTokenLifeTime: 60 * time.Second,
		Client:              client,
	}
	tokenService := authenticator.NewTokenService(tokenConfig)
	r.Use(middleware.NewTokenValidator(tokenService).RequireToken())

	publicRoute := r.Group("/enigma")
	publicRoute.POST("/auth", func(c *gin.Context) {
		var user model.Credential
		if err := c.BindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"message": "can't bind struct",
			})
			return
		}

		if user.Username == "enigma" && user.Password == "123" {
			token, err := tokenService.CreateAccessToken(&user)
			fmt.Println(err)
			if err != nil {
				c.AbortWithStatus(401)
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatus(401)
			return
		}
	})

	publicRoute.GET("/user", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": c.GetString("user-id"),
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}
