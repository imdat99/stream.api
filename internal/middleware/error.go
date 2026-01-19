package middleware

import (
	"log"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"stream.api/pkg/response"
)

// ErrorHandler is a middleware that handles errors attached to the context
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// If there are errors in the context
		if len(c.Errors) > 0 {
			// Log all errors
			for _, e := range c.Errors {
				log.Printf("Error: %v", e)
			}

			// Return the last error to the client using standard response
			// We can improve this map to specific status codes if we have custom error types
			lastError := c.Errors.Last()
			response.Error(c, http.StatusInternalServerError, lastError.Error())
		}
	}
}

// Recovery is a middleware that recovers from panics and returns a 500 error
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Log the stack trace
				log.Printf("Panic recovered: %v\n%s", err, debug.Stack())

				// Return 500 error using standard response
				response.Fail(c, "Internal Server Error")
			}
		}()
		c.Next()
	}
}
