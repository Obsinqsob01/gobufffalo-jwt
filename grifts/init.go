package grifts

import (
	"github.com/Obsinqsob01/jwt_boilerplate/actions"
	"github.com/gobuffalo/buffalo"
)

func init() {
	buffalo.Grifts(actions.App())
}
