package mesh

import (
	"errors"
	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
)

type serverState struct {
	Version int
	Node    key.NodePrivate
	PSK     tailcat.PresharedKey
}

func InitializeServer(string) error {
	return errors.New("mesh controller persistence requires a Unix host")
}
func WriteAddress(string, string) error {
	return errors.New("mesh controller persistence requires a Unix host")
}
func loadServerState(string) (serverState, func(), error) {
	return serverState{}, nil, errors.New("mesh controller persistence requires a Unix host")
}
