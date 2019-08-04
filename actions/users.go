package actions

import (
	"fmt"
	"net/http"
	"strings"
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
	return c.Render(200, r.JSON(map[string]string{
		"token": t,
	}))
}

// SetCurrentUser attempts to find a user based on the current_user_id
// in the session. If one is found it is set on the context.
func SetCurrentUser(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		tokenString := c.Request().Header.Get("Authorization")

		tokenString = strings.Split(tokenString, "Bearer ")[1]

		if len(tokenString) == 0 {
			return c.Error(http.StatusUnauthorized, fmt.Errorf("No token set in headers"))
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signin method: %v", token.Header["alg"])
			}

			// read the key
			// TODO: update by put key
			mySignedKey := []byte("secret")

			return mySignedKey, nil
		})

		if err != nil {
			return c.Error(http.StatusUnauthorized, fmt.Errorf("Could not parse the token, %v", err))
		}

		// Getting claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if ok && token.Valid {
			u := models.User{}
			tx := c.Value("tx").(*pop.Connection)

			tx.Find(&u, claims["Id"])

			c.Set("user", u)

			return next(c)
		}
		return c.Error(http.StatusUnauthorized, fmt.Errorf("Failed to validate token: %v", claims))
	}
}

// Authorize require a user be logged in before accessing a route
func Authorize(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		tokenString := c.Request().Header.Get("Authorization")

		tokenString = strings.Split(tokenString, "Bearer ")[1]

		if len(tokenString) == 0 {
			return c.Error(http.StatusUnauthorized, fmt.Errorf("No token set in headers"))
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signin method: %v", token.Header["alg"])
			}

			// read the key
			// TODO: update by put key
			mySignedKey := []byte("secret")

			return mySignedKey, nil
		})

		if err != nil {
			return c.Error(http.StatusUnauthorized, fmt.Errorf("Could not parse the token, %v", err))
		}

		// Getting claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if ok && token.Valid {
			u := models.User{}
			tx := c.Value("tx").(*pop.Connection)

			tx.Find(&u, claims["Id"])

			c.Set("user", u)

			return next(c)
		}

		return c.Error(http.StatusUnauthorized, fmt.Errorf("Failed to validate token: %v", claims))
	}
}

func ExampleHandler(c buffalo.Context) error {
	return c.Render(200, r.JSON("It works!"))
}
