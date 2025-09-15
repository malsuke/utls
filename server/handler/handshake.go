package handler

import (
	"github.com/labstack/echo/v4"
	"github.com/refraction-networking/utls/server/openapi"
)

type Server struct{}

func (s Server) PostTlsHandshake(ctx echo.Context) error {
	var payload openapi.HandshakeRequest
	if err := ctx.Bind(&payload); err != nil {
		return ctx.JSON(400, "Invalid payload")
	}

	return ctx.JSON(200, payload.CipherSuites)
}

func (s Server) PostTlsApplication(ctx echo.Context) error {
	return ctx.JSON(200, "ok")
}
