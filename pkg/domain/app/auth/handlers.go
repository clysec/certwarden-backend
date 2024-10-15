package auth

import (
	"certwarden-backend/pkg/httpclient"
	"certwarden-backend/pkg/output"
	"certwarden-backend/pkg/randomness"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// authResponse contains the JSON response for both
// login and session (session token is in a cookie
// so the JSON struct doesn't change)
type authResponse struct {
	output.JsonResponse
	Authorization authorization `json:"authorization"`
}

// loginPayload is the payload client's send to login
type loginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type OidcResponse struct {
	RedirectUrl string `json:"redirect_url"`
	State       string `json:"state"`
	Verifier    string `json:"verifier"`
	Challenge   string `json:"challenge"`
	CallbackUrl string `json:"callback_url"`
}

type OidcFormattedResponse struct {
	StatusCode int          `json:"status_code"`
	Message    string       `json:"message"`
	Data       OidcResponse `json:"authorization"`
}

type OidcLoginPayload struct {
	State           string       `json:"state"`
	SessionState    string       `json:"session_state"`
	Code            string       `json:"code"`
	Issuer          string       `json:"issuer"`
	OriginalRequest OidcResponse `json:"original_request"`
}

func (or *OidcFormattedResponse) HttpStatusCode() int {
	return http.StatusOK
}

// LoginUsingUserPwPayload takes the loginPayload, looks up the username in storage
// and validates the password. If so, an Access Token is returned in JSON and a refresh
// token is sent in a cookie.
func (service *Service) LoginUsingUserPwPayload(w http.ResponseWriter, r *http.Request) *output.Error {
	// wrap handler to easily check err and delete cookies
	outErr := func() *output.Error {
		var payload loginPayload

		// log attempt
		service.logger.Infof("client %s: attempting login", r.RemoteAddr)

		// decode body into payload
		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			service.logger.Infof("client %s: login failed (payload error: %s)", r.RemoteAddr, err)
			return output.ErrUnauthorized
		}

		// fetch the password hash from storage
		user, err := service.storage.GetOneUserByName(payload.Username)
		if err != nil {
			service.logger.Infof("client %s: login failed (bad username: %s)", r.RemoteAddr, err)
			return output.ErrUnauthorized
		}

		// compare
		err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.Password))
		if err != nil {
			service.logger.Infof("client %s: login failed (bad password: %s)", r.RemoteAddr, err)
			return output.ErrUnauthorized
		}

		// user and password now verified, make auth
		auth, err := service.newAuthorization(user.Username)
		if err != nil {
			service.logger.Errorf("client %s: login failed (internal error: %s)", r.RemoteAddr, err)
			return output.ErrInternal
		}

		// save auth's session in manager
		err = service.sessionManager.new(auth.SessionTokenClaims)
		if err != nil {
			service.logger.Errorf("client %s: login failed (internal error: %s)", r.RemoteAddr, err)
			return output.ErrUnauthorized
		}

		// return response to client
		response := &authResponse{}
		response.StatusCode = http.StatusOK
		response.Message = fmt.Sprintf("user '%s' logged in", auth.SessionTokenClaims.Subject)
		response.Authorization = auth

		// write response
		auth.writeSessionCookie(w)
		err = service.output.WriteJSON(w, response)
		if err != nil {
			service.logger.Errorf("failed to write json (%s)", err)
			return output.ErrWriteJsonError
		}

		// log success
		service.logger.Infof("client %s: user '%s' logged in", r.RemoteAddr, auth.SessionTokenClaims.Subject)

		return nil
	}()

	// if err, delete session cookie and return err
	if outErr != nil {
		service.deleteSessionCookie(w)
		return outErr
	}

	return nil
}

// LoginUsingUserPwPayload takes the loginPayload, looks up the username in storage
// and validates the password. If so, an Access Token is returned in JSON and a refresh
// token is sent in a cookie.
func (service *Service) StartOidcAuthProcess(w http.ResponseWriter, r *http.Request) *output.Error {
	// wrap handler to easily check err and delete cookies
	outErr := func() *output.Error {

		oidcIssuer := service.oidcConfig["issuerUrl"]
		oidcClientId := service.oidcConfig["clientId"]

		if oidcIssuer == "" || oidcClientId == "" {
			return output.ErrUnauthorized
		}

		codeVerifier, err := randomness.RandomHexBytes(32)
		if err != nil {
			return output.ErrInternal
		}

		sha2 := sha256.New()
		io.WriteString(sha2, codeVerifier)
		codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

		state, stateErr := randomness.RandomHexBytes(24)
		if stateErr != nil {
			return output.ErrInternal
		}

		authorizationUrl := service.oidcConfig["authorizationUrl"]
		if authorizationUrl == "" {
			return output.ErrInternal
		}

		redirectUrl := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=openid&state=%s&code_challenge=%s&code_challenge_method=S256", authorizationUrl, oidcClientId, state, codeChallenge)

		response := &OidcFormattedResponse{
			StatusCode: http.StatusOK,
			Message:    "user started oidc auth process",
			Data: OidcResponse{
				RedirectUrl: redirectUrl,
				State:       state,
				Verifier:    codeVerifier,
				Challenge:   codeChallenge,
			},
		}

		err = service.output.WriteJSON(w, response)
		if err != nil {
			service.logger.Errorf("failed to write json (%s)", err)
			return output.ErrWriteJsonError
		}

		service.logger.Infof("client %s: user started oidc auth process", r.RemoteAddr)
		return nil
	}()

	// if err, delete session cookie and return err
	if outErr != nil {
		service.deleteSessionCookie(w)
		return outErr
	}

	return nil
}

func (service *Service) LoginUserWithOidc(w http.ResponseWriter, r *http.Request) *output.Error {
	outErr := func() *output.Error {
		oidcIssuer := service.oidcConfig["issuerUrl"]
		oidcClientId := service.oidcConfig["clientId"]
		// oidcClientSecret := service.oidcConfig["clientSecret"]

		if oidcIssuer == "" || oidcClientId == "" {
			return output.ErrUnauthorized
		}

		request := OidcLoginPayload{}

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			return output.ErrUnauthorized
		}

		client := httpclient.New("oidc-client/1.0")

		body := fmt.Sprintf("grant_type=authorization_code&client_id=%s&code_verifier=%s&code=%s&redirect_uri=%s", oidcClientId, url.QueryEscape(request.OriginalRequest.Verifier), url.QueryEscape(request.Code), request.OriginalRequest.CallbackUrl)
		tokenResponse, err := client.Post(service.oidcConfig["tokenUrl"], "application/x-www-form-urlencoded", strings.NewReader(body))
		if err != nil {
			return output.ErrInternal
		}

		if tokenResponse.StatusCode != http.StatusOK {
			switch tokenResponse.StatusCode {
			case http.StatusInternalServerError:
				return output.ErrInternal
			case http.StatusUnauthorized, http.StatusForbidden:
				return output.ErrUnauthorized
			default:
				data, err := io.ReadAll(tokenResponse.Body)
				if err != nil {
					return output.ErrInternal
				}
				fmt.Println(string(data))
				return output.ErrInternal
			}
		}

		responseItem := map[string]interface{}{}
		err = json.NewDecoder(tokenResponse.Body).Decode(&responseItem)
		if err != nil {
			return output.ErrInternal
		}

		fmt.Println(responseItem)

		user, err := service.storage.GetOneUserByName("admin")
		if err != nil {
			service.logger.Infof("client %s: login failed (bad username: %s)", r.RemoteAddr, err)
			return output.ErrUnauthorized
		}

		// user and password now verified, make auth
		auth, err := service.newAuthorization(user.Username)
		if err != nil {
			service.logger.Errorf("client %s: login failed (internal error: %s)", r.RemoteAddr, err)
			return output.ErrInternal
		}
		// save auth's session in manager
		err = service.sessionManager.new(auth.SessionTokenClaims)
		if err != nil {
			service.logger.Errorf("client %s: login failed (internal error: %s)", r.RemoteAddr, err)
			return output.ErrUnauthorized
		}

		// return response to client
		response := &authResponse{}
		response.StatusCode = http.StatusOK
		response.Message = fmt.Sprintf("user '%s' logged in", auth.SessionTokenClaims.Subject)
		response.Authorization = auth

		// write response
		auth.writeSessionCookie(w)
		err = service.output.WriteJSON(w, response)
		if err != nil {
			service.logger.Errorf("failed to write json (%s)", err)
			return output.ErrWriteJsonError
		}

		// log success
		service.logger.Infof("client %s: user '%s' logged in", r.RemoteAddr, auth.SessionTokenClaims.Subject)

		return nil
	}()

	// if err, delete session cookie and return err
	if outErr != nil {
		service.deleteSessionCookie(w)
		return outErr
	}

	return nil
}

// RefreshUsingCookie validates the SessionToken cookie and confirms its UUID is for a valid
// session. If so, it generates a new AccessToken and new SessionToken cookie and then sends both
// to the client.
func (service *Service) RefreshUsingCookie(w http.ResponseWriter, r *http.Request) *output.Error {
	// wrap to easily check err and delete cookies
	outErr := func() *output.Error {
		// log attempt
		service.logger.Infof("client %s: attempting access token refresh", r.RemoteAddr)

		// validate cookie
		oldClaims, outErr := service.validateSessionCookie(r, w, "access token refresh")
		if outErr != nil {
			// error logged in validateCookieSession func and nice output error returned
			return outErr
		}

		// cookie & session verified, make new auth
		auth, err := service.newAuthorization(oldClaims.Subject)
		if err != nil {
			service.logger.Errorf("client %s: access token refresh failed (internal error: %s)", r.RemoteAddr, err)
			return output.ErrInternal
		}

		// refresh session in manager (remove old, add new)
		err = service.sessionManager.refresh(*oldClaims, auth.SessionTokenClaims)
		if err != nil {
			service.logger.Errorf("client %s: access token refresh failed (internal error: %s)", r.RemoteAddr, err)
			return output.ErrUnauthorized
		}

		// return response (new auth) to client
		response := &authResponse{}
		response.StatusCode = http.StatusOK
		response.Message = fmt.Sprintf("user '%s' access token refreshed", auth.SessionTokenClaims.Subject)
		response.Authorization = auth

		// write response
		auth.writeSessionCookie(w)
		err = service.output.WriteJSON(w, response)
		if err != nil {
			service.logger.Errorf("failed to write json (%s)", err)
			return output.ErrWriteJsonError
		}

		// log success
		service.logger.Infof("client %s: access token refresh for user '%s' succeeded", r.RemoteAddr, auth.SessionTokenClaims.Subject)

		return nil
	}()

	// if err, delete cookies and return err
	if outErr != nil {
		service.deleteSessionCookie(w)
		return outErr
	}

	return nil
}

// Logout logs the client out and removes the session from session manager
func (service *Service) Logout(w http.ResponseWriter, r *http.Request) *output.Error {
	// log attempt
	service.logger.Infof("client %s: attempting logout", r.RemoteAddr)

	// get claims from auth header
	oldClaims, err := service.ValidateAuthHeader(r, w, "logout")
	if err != nil {
		service.logger.Errorf("client %s: logout failed (%s)", r.RemoteAddr, oldClaims.Subject, err)
		return output.ErrUnauthorized
	}

	// remove session in manager
	err = service.sessionManager.close(*oldClaims)
	if err != nil {
		service.logger.Errorf("client %s: logout for user '%s' failed (%s)", r.RemoteAddr, oldClaims.Subject, err)
		return output.ErrUnauthorized
	}

	// log success
	service.logger.Infof("client %s: logout for user '%s' succeeded", r.RemoteAddr, oldClaims.Subject)

	// return response (logged out)
	response := &output.JsonResponse{}
	response.StatusCode = http.StatusOK
	response.Message = fmt.Sprintf("user '%s' logged out", oldClaims.Subject)
	// delete session cookie
	service.deleteSessionCookie(w)

	err = service.output.WriteJSON(w, response)
	if err != nil {
		service.logger.Errorf("failed to write json (%s)", err)
		return output.ErrWriteJsonError
	}

	return nil
}

// passwordChangePayload contains the expected payload fields for
// a user changing their password
type passwordChangePayload struct {
	CurrentPassword    string `json:"current_password"`
	NewPassword        string `json:"new_password"`
	ConfirmNewPassword string `json:"confirm_new_password"`
}

// ChangePassword allows a user to change their password
func (service *Service) ChangePassword(w http.ResponseWriter, r *http.Request) *output.Error {
	// log attempt
	service.logger.Infof("client %s: attempting password change", r.RemoteAddr)

	// validate jwt and get the claims (to confirm the username)
	claims, err := service.ValidateAuthHeader(r, w, "password change")
	if err != nil {
		service.logger.Infof("client %s: password change failed (bad auth header: %s)", r.RemoteAddr, err)
		return output.ErrUnauthorized
	}
	username := claims.Subject

	// decode body into payload
	var payload passwordChangePayload
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		service.logger.Infof("client %s: password change for user '%s' failed (payload error: %s)", r.RemoteAddr, username, err)
		return output.ErrUnauthorized
	}

	// fetch the password hash from storage
	user, err := service.storage.GetOneUserByName(username)
	if err != nil {
		// shouldn't be possible since header was valid
		service.logger.Errorf("client %s: password change for user '%s' failed (bad username: %s)", r.RemoteAddr, username, err)
		return output.ErrUnauthorized
	}

	// confirm current password is correct
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.CurrentPassword))
	if err != nil {
		service.logger.Infof("client %s: password change for user '%s' failed (bad password: %s)", r.RemoteAddr, username, err)
		return output.ErrUnauthorized
	}

	// verify new password matches
	if payload.NewPassword != payload.ConfirmNewPassword {
		service.logger.Infof("client %s: password change for user '%s' failed (new password did not match confirmation)", r.RemoteAddr, username)
		return output.ErrValidationFailed
	}

	// don't enforce any password requirements other than it needs to exist
	if len(payload.NewPassword) < 1 {
		service.logger.Infof("client %s: password change for user '%s' failed (new password not specified)", r.RemoteAddr, username)
		return output.ErrValidationFailed
	}

	// generate new password hash
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), BcryptCost)
	if err != nil {
		service.logger.Errorf("client %s: password change for user '%s' failed (internal error: %s)", r.RemoteAddr, username, err)
		return output.ErrInternal
	}

	// update password in storage
	userId, err := service.storage.UpdateUserPassword(username, string(newPasswordHash))
	if err != nil {
		service.logger.Errorf("client %s: password change for user '%s' failed (internal error: %s)", r.RemoteAddr, username, err)
		return output.ErrStorageGeneric
	}

	// log success (before response since new pw already saved)
	service.logger.Infof("client %s: password change for user '%s' succeeded", r.RemoteAddr, username)

	// return response to client
	response := &output.JsonResponse{}
	response.StatusCode = http.StatusOK
	response.Message = fmt.Sprintf("password changed for user '%s' (id: %d)", username, userId)

	err = service.output.WriteJSON(w, response)
	if err != nil {
		service.logger.Errorf("failed to write json (%s)", err)
		return output.ErrWriteJsonError
	}

	return nil
}
