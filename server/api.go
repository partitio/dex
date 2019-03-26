package server

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	// go-grpc doesn't use the standard library's context.
	// https://github.com/grpc/grpc-go/issues/711
	"golang.org/x/net/context"

	"github.com/partitio/dex/api"
	"github.com/partitio/dex/pkg/log"
	"github.com/partitio/dex/server/pb"
	"github.com/partitio/dex/storage"
	"github.com/partitio/dex/version"
)

// apiVersion increases every time a new call is added to the API. Clients should use this info
// to determine if the server supports specific features.
const apiVersion = 2

const (
	// recCost is the recommended bcrypt cost, which balances hash strength and
	// efficiency.
	recCost = 12

	// upBoundCost is a sane upper bound on bcrypt cost determined by benchmarking:
	// high enough to ensure secure encryption, low enough to not put unnecessary
	// load on a dex server.
	upBoundCost = 16

	DexAPI = "dex-api"
)

// NewAPI returns a server which implements the gRPC API interface.
func NewAPI(s storage.Storage, logger log.Logger) api.DexHandler {
	return dexAPI{
		s:      s,
		logger: logger,
	}
}

type dexAPI struct {
	s      storage.Storage
	logger log.Logger
}

func (d dexAPI) CreateClient(ctx context.Context, req *api.CreateClientReq, res *api.CreateClientResp) error {
	if req.Client == nil {
		return errors.New("no client supplied")
	}

	if req.Client.Id == "" {
		req.Client.Id = storage.NewID()
	}
	if req.Client.Secret == "" {
		req.Client.Secret = storage.NewID() + storage.NewID()
	}

	c := storage.Client{
		ID:           req.Client.Id,
		Secret:       req.Client.Secret,
		RedirectURIs: req.Client.RedirectUris,
		TrustedPeers: req.Client.TrustedPeers,
		Public:       req.Client.Public,
		Name:         req.Client.Name,
		LogoURL:      req.Client.LogoUrl,
	}
	if err := d.s.CreateClient(c); err != nil {
		if err == storage.ErrAlreadyExists {
			res.AlreadyExists = true
			return nil
		}
		d.logger.Errorf("api: failed to create client: %v", err)
		return fmt.Errorf("create client: %v", err)
	}

	res.Client = req.Client
	return nil
}

func (d dexAPI) UpdateClient(ctx context.Context, req *api.UpdateClientReq, res *api.UpdateClientResp) error {
	if req.Id == "" {
		return errors.New("update client: no client ID supplied")
	}

	err := d.s.UpdateClient(req.Id, func(old storage.Client) (storage.Client, error) {
		if req.RedirectUris != nil {
			old.RedirectURIs = req.RedirectUris
		}
		if req.TrustedPeers != nil {
			old.TrustedPeers = req.TrustedPeers
		}
		if req.Name != "" {
			old.Name = req.Name
		}
		if req.LogoUrl != "" {
			old.LogoURL = req.LogoUrl
		}
		return old, nil
	})

	if err != nil {
		if err == storage.ErrNotFound {
			res.NotFound = true
			return nil
		}
		d.logger.Errorf("api: failed to update the client: %v", err)
		return fmt.Errorf("update client: %v", err)
	}
	return nil
}

func (d dexAPI) DeleteClient(ctx context.Context, req *api.DeleteClientReq, res *api.DeleteClientResp) error {
	err := d.s.DeleteClient(req.Id)
	if err != nil {
		if err == storage.ErrNotFound {
			res.NotFound = true
			return nil
		}
		d.logger.Errorf("api: failed to delete client: %v", err)
		return fmt.Errorf("delete client: %v", err)
	}
	return nil
}

// checkCost returns an error if the hash provided does not meet lower or upper
// bound cost requirements.
func checkCost(hash []byte) error {
	actual, err := bcrypt.Cost(hash)
	if err != nil {
		return fmt.Errorf("parsing bcrypt hash: %v", err)
	}
	if actual < bcrypt.DefaultCost {
		return fmt.Errorf("given hash cost = %d does not meet minimum cost requirement = %d", actual, bcrypt.DefaultCost)
	}
	if actual > upBoundCost {
		return fmt.Errorf("given hash cost = %d is above upper bound cost = %d, recommended cost = %d", actual, upBoundCost, recCost)
	}
	return nil
}

func (d dexAPI) CreatePassword(ctx context.Context, req *api.CreatePasswordReq, res *api.CreatePasswordResp) error {
	if req.Password == nil {
		return errors.New("no password supplied")
	}
	if req.Password.UserId == "" {
		return errors.New("no user ID supplied")
	}
	if req.Password.Hash != nil {
		if err := checkCost(req.Password.Hash); err != nil {
			return err
		}
	} else {
		return errors.New("no hash of password supplied")
	}

	p := storage.Password{
		Email:    req.Password.Email,
		Hash:     req.Password.Hash,
		Username: req.Password.Username,
		UserID:   req.Password.UserId,
	}
	if err := d.s.CreatePassword(p); err != nil {
		if err == storage.ErrAlreadyExists {
			res.AlreadyExists = true
			return nil
		}
		d.logger.Errorf("api: failed to create password: %v", err)
		return fmt.Errorf("create password: %v", err)
	}

	return nil
}

func (d dexAPI) UpdatePassword(ctx context.Context, req *api.UpdatePasswordReq, res *api.UpdatePasswordResp) error {
	if req.Email == "" {
		return errors.New("no email supplied")
	}
	if req.NewHash == nil && req.NewUsername == "" {
		return errors.New("nothing to update")
	}

	if req.NewHash != nil {
		if err := checkCost(req.NewHash); err != nil {
			return err
		}
	}

	updater := func(old storage.Password) (storage.Password, error) {
		if req.NewHash != nil {
			old.Hash = req.NewHash
		}

		if req.NewUsername != "" {
			old.Username = req.NewUsername
		}

		return old, nil
	}

	if err := d.s.UpdatePassword(req.Email, updater); err != nil {
		if err == storage.ErrNotFound {
			res.NotFound = true
			return nil
		}
		d.logger.Errorf("api: failed to update password: %v", err)
		return fmt.Errorf("update password: %v", err)
	}

	return nil
}

func (d dexAPI) DeletePassword(ctx context.Context, req *api.DeletePasswordReq, res *api.DeletePasswordResp) error {
	if req.Email == "" {
		return errors.New("no email supplied")
	}

	err := d.s.DeletePassword(req.Email)
	if err != nil {
		if err == storage.ErrNotFound {
			res.NotFound = true
			return nil
		}
		d.logger.Errorf("api: failed to delete password: %v", err)
		return fmt.Errorf("delete password: %v", err)
	}
	return nil

}

func (d dexAPI) GetVersion(ctx context.Context, req *api.VersionReq, res *api.VersionResp) error {
	res.Server = version.Version
	res.Api = apiVersion
	return nil
}

func (d dexAPI) ListPasswords(ctx context.Context, req *api.ListPasswordReq, res *api.ListPasswordResp) error {
	passwordList, err := d.s.ListPasswords()
	if err != nil {
		d.logger.Errorf("api: failed to list passwords: %v", err)
		return fmt.Errorf("list passwords: %v", err)
	}

	var passwords []*api.Password
	for _, password := range passwordList {
		p := api.Password{
			Email:    password.Email,
			Username: password.Username,
			UserId:   password.UserID,
		}
		passwords = append(passwords, &p)
	}

	res.Passwords = passwords
	return nil

}

func (d dexAPI) ListRefresh(ctx context.Context, req *api.ListRefreshReq, res *api.ListRefreshResp) error {
	id := new(pb.IDTokenSubject)
	if err := pb.Unmarshal(req.UserId, id); err != nil {
		d.logger.Errorf("api: failed to unmarshal ID Token subject: %v", err)
		return err
	}

	var refreshTokenRefs []*api.RefreshTokenRef
	offlineSessions, err := d.s.GetOfflineSessions(id.UserId, id.ConnId)
	if err != nil {
		if err == storage.ErrNotFound {
			// This means that this user-client pair does not have a refresh token yet.
			// An empty list should be returned instead of an error.
			res.RefreshTokens = refreshTokenRefs
			return nil
		}
		d.logger.Errorf("api: failed to list refresh tokens %t here : %v", err == storage.ErrNotFound, err)
		return err
	}

	for _, session := range offlineSessions.Refresh {
		r := api.RefreshTokenRef{
			Id:        session.ID,
			ClientId:  session.ClientID,
			CreatedAt: session.CreatedAt.Unix(),
			LastUsed:  session.LastUsed.Unix(),
		}
		refreshTokenRefs = append(refreshTokenRefs, &r)
	}

	res.RefreshTokens = refreshTokenRefs
	return nil
}

func (d dexAPI) RevokeRefresh(ctx context.Context, req *api.RevokeRefreshReq, res *api.RevokeRefreshResp) error {
	id := new(pb.IDTokenSubject)
	if err := pb.Unmarshal(req.UserId, id); err != nil {
		d.logger.Errorf("api: failed to unmarshal ID Token subject: %v", err)
		return err
	}

	var (
		refreshID string
		notFound  bool
	)
	updater := func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		refreshRef := old.Refresh[req.ClientId]
		if refreshRef == nil || refreshRef.ID == "" {
			d.logger.Errorf("api: refresh token issued to client %q for user %q not found for deletion", req.ClientId, id.UserId)
			notFound = true
			return old, storage.ErrNotFound
		}

		refreshID = refreshRef.ID

		// Remove entry from Refresh list of the OfflineSession object.
		delete(old.Refresh, req.ClientId)

		return old, nil
	}

	if err := d.s.UpdateOfflineSessions(id.UserId, id.ConnId, updater); err != nil {
		if err == storage.ErrNotFound {
			res.NotFound = true
			return nil
		}
		d.logger.Errorf("api: failed to update offline session object: %v", err)
		return err
	}

	if notFound {
		res.NotFound = true
		return nil
	}

	// Delete the refresh token from the storage
	//
	// TODO(ericchiang): we don't have any good recourse if this call fails.
	// Consider garbage collection of refresh tokens with no associated ref.
	if err := d.s.DeleteRefresh(refreshID); err != nil {
		d.logger.Errorf("failed to delete refresh token: %v", err)
		return err
	}

	return nil
}
