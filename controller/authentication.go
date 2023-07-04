package controller

import (
	"example/hello/helper"
	model "example/hello/models"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

var privateKey = []byte(os.Getenv("JWT_PRIVATE_KEY"))

func Register(context *gin.Context) {
	var input model.AuthenticationInput

	if err := context.ShouldBindJSON(&input); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := model.User{
		Username: input.Username,
		Password: input.Password,
	}

	savedUser, err := user.Save()

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	context.JSON(http.StatusCreated, gin.H{"user": savedUser})
}

func Login(context *gin.Context) {
	var input model.AuthenticationInput

	if err := context.ShouldBindJSON(&input); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	user, err := model.FindUserByUsername(input.Username)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	err = user.ValidatePassword(input.Password)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jwt := helper.GenerateJWT(user.ID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// jwtJSON, _ := json.Marshal(jwt)
	// context.SetCookie("token", jwtJSON, 60, "", "", true, true)

	context.JSON(http.StatusOK, gin.H{"jwt": jwt})

}

func RefreshToken(context *gin.Context) {
	tokens, err := helper.RefreshToken(context)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}
	context.JSON(http.StatusOK, gin.H{"jwt": tokens})

}
