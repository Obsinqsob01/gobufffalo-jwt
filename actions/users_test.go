package actions

import (
	"github.com/Obsinqsob01/jwt_boilerplate/models"
)

func (as *ActionSuite) Test_Users_Create() {
	count, err := as.DB.Count("users")
	as.NoError(err)
	as.Equal(0, count)

	u := &models.User{
		Email:                "mark@example.com",
		Password:             "password",
		PasswordConfirmation: "password",
	}

	res := as.HTML("/users").Post(u)
	as.Equal(302, res.Code)
	as.Contains(res.Body.String(), "token")

	count, err = as.DB.Count("users")
	as.NoError(err)
	as.Equal(1, count)
}
