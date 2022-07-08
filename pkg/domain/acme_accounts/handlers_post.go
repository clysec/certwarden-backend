package acme_accounts

import (
	"encoding/json"
	"legocerthub-backend/pkg/output"
	"legocerthub-backend/pkg/utils"
	"net/http"
)

// NewPayload is the struct for creating a new account
type NewPayload struct {
	ID           *int    `json:"id"`
	Name         *string `json:"name"`
	Description  *string `json:"description"`
	Email        *string `json:"email"`
	PrivateKeyID *int    `json:"private_key_id"`
	IsStaging    *bool   `json:"is_staging"`
	AcceptedTos  *bool   `json:"accepted_tos"`
}

func (service *Service) PostNewAccount(w http.ResponseWriter, r *http.Request) (err error) {
	var payload NewPayload

	// decode body into payload
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		service.logger.Debug(err)
		return output.ErrValidationFailed
	}

	/// do validation
	// id
	err = utils.IsIdNew(payload.ID)
	if err != nil {
		service.logger.Debug(err)
		return output.ErrValidationFailed
	}
	// name
	err = service.isNameValid(payload.ID, payload.Name)
	if err != nil {
		service.logger.Debug(err)
		return output.ErrValidationFailed
	}
	// email
	err = utils.IsEmailValidOrBlank(payload.Email)
	if err != nil {
		service.logger.Debug(err)
		return output.ErrValidationFailed
	}
	// TOS must be accepted
	if !*payload.AcceptedTos {
		service.logger.Debug(err)
		return output.ErrValidationFailed
	}
	// private key
	err = service.keys.IsPrivateKeyValid(payload.PrivateKeyID)
	if err != nil {
		service.logger.Debug(err)
		return output.ErrValidationFailed
	}
	///

	// Save new account details to storage.
	// No ACME actions are performed.
	account, err := service.storage.PostNewAccount(payload)
	if err != nil {
		service.logger.Error(err)
		return output.ErrStorageGeneric
	}

	// return response to client
	_, err = output.WriteJSON(w, http.StatusCreated, account, "acme_account")
	if err != nil {
		service.logger.Error(err)
		return output.ErrWriteJsonFailed
	}

	return nil
}
