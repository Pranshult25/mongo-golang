package main

import (
	"fmt"
	"os"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/pranshult25/queriesportalbackend/common"
	"github.com/pranshult25/queriesportalbackend/router"
)

func main() {
	err := run()

	if err != nil {
		fmt.Println("oh no")
		panic(err)
	}
}

func run() error {
	// init env
	err := common.LoadEnv()
	if err != nil {
		fmt.Println("hello")
		return err
	}

	// init db
	err = common.InitDB()
	if err != nil {
		fmt.Println("hello2")
		return err
	}

	// defer closing db
	defer common.CloseDB()

	// create app
	app := fiber.New()

	// add basic middleware
	app.Use(logger.New())
	app.Use(recover.New())
	app.Use(cors.New())

	// add routes
	router.Router(app)

	// start server
	var port string
	if port = os.Getenv("PORT"); port == "" {
		port = "3000"
	}
	app.Listen(":" + port)

	return nil
}