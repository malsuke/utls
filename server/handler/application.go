package handler

import "github.com/labstack/echo/v4"

func (s Server) PostTlsApplication(ctx echo.Context) error {
	return ctx.JSON(200, "ok")
}
