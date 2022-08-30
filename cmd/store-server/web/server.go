package web

import "github.com/go-redis/redis/v9"

type Server struct {
	rdb *redis.Client
}
