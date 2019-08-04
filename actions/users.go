package actions

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Obsinqsob01/jwt_boilerplate/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/pop"
	"github.com/pkg/errors"
)

// UsersCreate registers a new user with the application.
func UsersCreate(c buffalo.Context) error {
	u := &models.User{}
	if err := c.Bind(u); err != nil {
		return errors.WithStack(err)
	}

	tx := c.Value("tx").(*pop.Connection)
	verrs, err := u.Create(tx)
	if err != nil {
		return errors.WithStack(err)
	}

	if verrs.HasAny() {
		return c.Render(401, r.JSON(verrs))
	}

	// Create Token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set Claims
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = u.FullName()
	claims["id"] = u.ID
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	// Generate encoded token and send it as response
	// TODO: Change secret string by put your key
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return err
	}

	// Return token
	return c.Render(200, r.JSON(map[string]string{
		"token": t,
	}))
}

// SetCurrentUser attempts to find a user based on the current_user_id
// in the session. If one is found it is set on the context.
func SetCurrentUser(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		if uid := c.Session().Get("current_user_id"); uid != nil {
			u := &models.User{}
			tx := c.Value("tx").(*pop.Connection)
			err := tx.Find(u, uid)
			if err != nil {
				return errors.WithStack(err)
			}
			c.Set("current_user", u)
		}
		return next(c)
	}
}

// Authorize require a user be logged in before accessing a route
func Authorize(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		tokenString := c.Request().Header.Get("Authorization")

		if len(tokenString) == 0 {
			return c.Error(http.StatusUnauthorized, fmt.Errorf("No token set in headers"))
		}

		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signin method: %v", token.Header["alg"])
			}

			// read the key
			// TODO: update by put key
			mySignedKey := "secret"

			return mySignedKey, nil

		})

		// Getting claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if ok && token.Valid {
			u := models.User{}
			tx := c.Value("tx").(*pop.Connection)

			tx.Find(&u, claims["id"])

			c.Set("user", u)

			return next(c)
		}

		return c.Error(http.StatusUnauthorized, fmt.Errorf("Failed to validate token: %v", claims))
	}
}
