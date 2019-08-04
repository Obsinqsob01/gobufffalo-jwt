package actions

import (
	"database/sql"
	"strings"
	"time"

	"github.com/Obsinqsob01/jwt_boilerplate/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/pop"
	"github.com/gobuffalo/validate"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// AuthCreate attempts to log the user in with an existing account.
func AuthCreate(c buffalo.Context) error {
	u := &models.User{}
	if err := c.Bind(u); err != nil {
		return errors.WithStack(err)
	}

	tx := c.Value("tx").(*pop.Connection)

	// find a user with the email
	err := tx.Where("email = ?", strings.ToLower(strings.TrimSpace(u.Email))).First(u)

	// helper function to handle bad attempts
	bad := func() error {
		c.Set("user", u)
		verrs := validate.NewErrors()
		verrs.Add("email", "invalid email/password")
		return c.Render(422, r.JSON(verrs))
	}

	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			// couldn't find an user with the supplied email address.
			return bad()
		}
		return errors.WithStack(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(u.Password))
	if err != nil {
		return bad()
	}

	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
		Id:        u.ID.String(),
	}

	// Create Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response
	// TODO: Change secret string by put your key
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return err
	}

	// Return token
	return c.Render(302, r.JSON(map[string]string{
		"token": t,
	}))

}
