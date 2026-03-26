package payments

import (
	"net/http"

	"google.golang.org/grpc/codes"
	"stream.api/internal/modules/common"
)

func newValidationError(message string, data map[string]any) *PaymentValidationError {
	return &PaymentValidationError{
		GRPCCode: int(codes.InvalidArgument),
		HTTPCode: http.StatusBadRequest,
		Message:  message,
		Data:     data,
	}
}

func (e *PaymentValidationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *PaymentValidationError) apiBody() common.APIErrorBody {
	return common.APIErrorBody{
		Code:    e.HTTPCode,
		Message: e.Message,
		Data:    e.Data,
	}
}

