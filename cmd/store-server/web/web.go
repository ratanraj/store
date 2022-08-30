package web

import (
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v9"
)

func RunServer() error {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: "",
		DB:       0,
	})

	server := &Server{
		rdb: rdb,
	}
	r := gin.Default()

	r.GET("/", server.Home)
	r.POST("/register", server.Register)
	r.POST("/message", server.Message)

	return r.Run()
}
