package server

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/refraction-networking/utls/server/handler"
	"github.com/refraction-networking/utls/server/openapi"
)

func Run() {
	e := echo.New()
	e.Use(middleware.Logger())
	server := handler.Server{}
	e.Static("/static", "/Users/yuki/tools/tls-packet-sender/out/")
	openapi.RegisterHandlers(e, server)
	e.Logger.Fatal(e.Start(":8080"))
}
