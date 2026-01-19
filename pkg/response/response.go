package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Success sends a success response with 200 OK
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Message: "success",
		Data:    data,
	})
}

// Created sends a success response with 201 Created
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, Response{
		Code:    http.StatusCreated,
		Message: "created",
		Data:    data,
	})
}

// Error sends an error response with the specified status code
func Error(c *gin.Context, code int, message string) {
	c.AbortWithStatusJSON(code, Response{
		Code:    code,
		Message: message,
	})
}

// Fail sends an internal server error response (500)
func Fail(c *gin.Context, message string) {
	Error(c, http.StatusInternalServerError, message)
}
