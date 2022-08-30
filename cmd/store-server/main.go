package main

import (
	"log"

	"github.com/ratanraj/store/cmd/store-server/web"
)

func main() {
	log.Fatal(web.RunServer())
}
