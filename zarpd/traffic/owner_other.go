//go:build !darwin || !cgo

package traffic

import (
	"context"
	"errors"
	"github.com/feg55/zarp-macos/zarpd/tunproxy"
)

func NativeOwnerSupported() bool { return false }

type NativeOwners struct{}

func (*NativeOwners) Owner(context.Context, tunproxy.Flow) (Owner, error) {
	return Owner{}, errors.New("application ownership is unavailable")
}
