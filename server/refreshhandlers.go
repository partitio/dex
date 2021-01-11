package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

func contains(arr []string, item string) bool {
	for _, itemFromArray := range arr {
		if itemFromArray == item {
			return true
		}
	}
	return false
}

type refreshError struct {
	msg  string
	code int
	desc string
}

func (s *Server) refreshTokenErrHelper(w http.ResponseWriter, err *refreshError) {
	s.tokenErrHelper(w, err.msg, err.desc, err.code)
}

func (s *Server) extractRefreshTokenFromRequest(r *http.Request) (*internal.RefreshToken, *refreshError) {
	code := r.PostFormValue("refresh_token")
	if code == "" {
		return nil, &refreshError{msg: errInvalidRequest, desc: "No refresh token in request.", code: http.StatusBadRequest}
	}

	token := new(internal.RefreshToken)
	if err := internal.Unmarshal(code, token); err != nil {
		// For backward compatibility, assume the refresh_token is a raw refresh token ID
		// if it fails to decode.
		//
		// Because refresh_token values that aren't unmarshable were generated by servers
		// that don't have a Token value, we'll still reject any attempts to claim a
		// refresh_token twice.
		token = &internal.RefreshToken{RefreshId: code, Token: ""}
	}

	return token, nil
}

// getRefreshTokenFromStorage checks that refresh token is valid and exists in the storage and gets its info
func (s *Server) getRefreshTokenFromStorage(clientID string, token *internal.RefreshToken) (storage.RefreshToken, *refreshError) {
	refresh, err := s.storage.GetRefresh(token.RefreshId)
	rerr := refreshError{
		msg:  errInvalidRequest,
		desc: "Refresh token is invalid or has already been claimed by another client.",
		code: http.StatusBadRequest,
	}

	if err != nil {
		s.logger.Errorf("failed to get refresh token: %v", err)
		if err != storage.ErrNotFound {
			return storage.RefreshToken{}, &refreshError{msg: errInvalidRequest, desc: "", code: http.StatusInternalServerError}
		}

		return storage.RefreshToken{}, &rerr
	}

	if refresh.ClientID != clientID {
		s.logger.Errorf("client %s trying to claim token for client %s", clientID, refresh.ClientID)
		return storage.RefreshToken{}, &rerr
	}

	if refresh.Token != token.Token {
		switch {
		case !s.refreshTokenPolicy.AllowedToReuse(refresh.LastUsed):
			fallthrough
		case refresh.ObsoleteToken != token.Token:
			fallthrough
		case refresh.ObsoleteToken == "":
			s.logger.Errorf("refresh token with id %s claimed twice", refresh.ID)
			return storage.RefreshToken{}, &rerr
		}
	}

	rerr.desc = "Refresh token expired."
	if s.refreshTokenPolicy.CompletelyExpired(refresh.CreatedAt) {
		s.logger.Errorf("refresh token with id %s expired", refresh.ID)
		return storage.RefreshToken{}, &rerr
	}

	if s.refreshTokenPolicy.ExpiredBecauseUnused(refresh.LastUsed) {
		s.logger.Errorf("refresh token with id %s expired because being unused", refresh.ID)
		return storage.RefreshToken{}, &rerr
	}

	return refresh, nil
}

func (s *Server) getRefreshScopes(r *http.Request, refresh *storage.RefreshToken) ([]string, *refreshError) {
	// Per the OAuth2 spec, if the client has omitted the scopes, default to the original
	// authorized scopes.
	//
	// https://tools.ietf.org/html/rfc6749#section-6
	scope := r.PostFormValue("scope")

	if scope == "" {
		return refresh.Scopes, nil
	}

	requestedScopes := strings.Fields(scope)
	var unauthorizedScopes []string

	// Per the OAuth2 spec, if the client has omitted the scopes, default to the original
	// authorized scopes.
	//
	// https://tools.ietf.org/html/rfc6749#section-6
	for _, requestScope := range requestedScopes {
		if !contains(refresh.Scopes, requestScope) {
			unauthorizedScopes = append(unauthorizedScopes, requestScope)
		}
	}

	if len(unauthorizedScopes) > 0 {
		desc := fmt.Sprintf("Requested scopes contain unauthorized scope(s): %q.", unauthorizedScopes)
		return nil, &refreshError{msg: errInvalidRequest, desc: desc, code: http.StatusBadRequest}
	}

	return requestedScopes, nil
}

func (s *Server) refreshWithConnector(ctx context.Context, token *internal.RefreshToken, refresh *storage.RefreshToken, scopes []string) (connector.Identity, *refreshError) {
	var connectorData []byte
	rerr := refreshError{msg: errInvalidRequest, desc: "", code: http.StatusInternalServerError}

	session, err := s.storage.GetOfflineSessions(refresh.Claims.UserID, refresh.ConnectorID)
	switch {
	case err != nil:
		if err != storage.ErrNotFound {
			s.logger.Errorf("failed to get offline session: %v", err)
			// TODO: previously there was a naked return without writing anything in response, need to figure it out
			return connector.Identity{}, &rerr
		}
	case len(refresh.ConnectorData) > 0:
		// Use the old connector data if it exists, should be deleted once used
		connectorData = refresh.ConnectorData
	default:
		connectorData = session.ConnectorData
	}

	conn, err := s.getConnector(refresh.ConnectorID)
	if err != nil {
		s.logger.Errorf("connector with ID %q not found: %v", refresh.ConnectorID, err)
		return connector.Identity{}, &rerr
	}

	ident := connector.Identity{
		UserID:            refresh.Claims.UserID,
		Username:          refresh.Claims.Username,
		PreferredUsername: refresh.Claims.PreferredUsername,
		Email:             refresh.Claims.Email,
		EmailVerified:     refresh.Claims.EmailVerified,
		Groups:            refresh.Claims.Groups,
		ConnectorData:     connectorData,
	}

	// user's token was previously updated by a connector and is allowed to reuse
	// it is excessive to refresh identity in upstream
	if s.refreshTokenPolicy.AllowedToReuse(refresh.LastUsed) && token.Token == refresh.ObsoleteToken {
		return ident, nil
	}

	// Can the connector refresh the identity? If so, attempt to refresh the data
	// in the connector.
	//
	// TODO(ericchiang): We may want a strict mode where connectors that don't implement
	// this interface can't perform refreshing.
	if refreshConn, ok := conn.Connector.(connector.RefreshConnector); ok {
		newIdent, err := refreshConn.Refresh(ctx, parseScopes(scopes), ident)
		if err != nil {
			s.logger.Errorf("failed to refresh identity: %v", err)
			return connector.Identity{}, &rerr
		}
		ident = newIdent
	}

	return ident, nil
}

// updateRefreshToken updates refresh token and offline session in the storage
func (s *Server) updateRefreshToken(token *internal.RefreshToken, refresh *storage.RefreshToken, ident connector.Identity) (*internal.RefreshToken, *refreshError) {
	newToken := token
	if s.refreshTokenPolicy.RotationEnabled() {
		newToken = &internal.RefreshToken{
			RefreshId: refresh.ID,
			Token:     storage.NewID(),
		}
	}

	lastUsed := s.now()
	refreshTokenUpdater := func(old storage.RefreshToken) (storage.RefreshToken, error) {
		if s.refreshTokenPolicy.RotationEnabled() {
			if old.Token != refresh.Token {
				if s.refreshTokenPolicy.AllowedToReuse(old.LastUsed) && old.ObsoleteToken == refresh.Token {
					newToken.Token = old.Token
					return old, nil
				}
				return old, errors.New("refresh token claimed twice")
			}

			old.ObsoleteToken = old.Token
		}

		old.Token = newToken.Token
		// Update the claims of the refresh token.
		//
		// UserID intentionally ignored for now.
		old.Claims.Username = ident.Username
		old.Claims.PreferredUsername = ident.PreferredUsername
		old.Claims.Email = ident.Email
		old.Claims.EmailVerified = ident.EmailVerified
		old.Claims.Groups = ident.Groups
		old.LastUsed = lastUsed

		// ConnectorData has been moved to OfflineSession
		old.ConnectorData = []byte{}
		return old, nil
	}

	offlineSessionUpdater := func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		if old.Refresh[refresh.ClientID].ID != refresh.ID {
			return old, errors.New("refresh token invalid")
		}
		old.Refresh[refresh.ClientID].LastUsed = lastUsed
		old.ConnectorData = ident.ConnectorData
		return old, nil
	}

	rerr := refreshError{msg: errInvalidRequest, desc: "", code: http.StatusInternalServerError}

	// Update LastUsed time stamp in refresh token reference object
	// in offline session for the user.
	err := s.storage.UpdateOfflineSessions(refresh.Claims.UserID, refresh.ConnectorID, offlineSessionUpdater)
	if err != nil {
		s.logger.Errorf("failed to update offline session: %v", err)
		return newToken, &rerr
	}

	// Update refresh token in the storage.
	err = s.storage.UpdateRefreshToken(refresh.ID, refreshTokenUpdater)
	if err != nil {
		s.logger.Errorf("failed to update refresh token: %v", err)
		return newToken, &rerr
	}

	return newToken, nil
}

// handleRefreshToken handles a refresh token request https://tools.ietf.org/html/rfc6749#section-6
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request, client storage.Client) {
	token, rerr := s.extractRefreshTokenFromRequest(r)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	refresh, rerr := s.getRefreshTokenFromStorage(client.ID, token)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	scopes, rerr := s.getRefreshScopes(r, &refresh)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	ident, rerr := s.refreshWithConnector(r.Context(), token, &refresh, scopes)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	claims := storage.Claims{
		UserID:            ident.UserID,
		Username:          ident.Username,
		PreferredUsername: ident.PreferredUsername,
		Email:             ident.Email,
		EmailVerified:     ident.EmailVerified,
		Groups:            ident.Groups,
	}

	accessToken, err := s.newAccessToken(client.ID, claims, scopes, refresh.Nonce, refresh.ConnectorID)
	if err != nil {
		s.logger.Errorf("failed to create new access token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	idToken, expiry, err := s.newIDToken(client.ID, claims, scopes, refresh.Nonce, accessToken, refresh.ConnectorID)
	if err != nil {
		s.logger.Errorf("failed to create ID token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	newToken, rerr := s.updateRefreshToken(token, &refresh, ident)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	rawNewToken, err := internal.Marshal(newToken)
	if err != nil {
		s.logger.Errorf("failed to marshal refresh token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	resp := s.toAccessTokenResponse(idToken, accessToken, rawNewToken, expiry)
	s.writeAccessToken(w, resp)
}
