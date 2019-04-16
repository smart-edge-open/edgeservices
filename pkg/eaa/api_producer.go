package eaa

import (
	"errors"
)

func addService(serv Service) error {
	if eaaCtx.serviceInfo == nil {
		return errors.New(
			"EAA context is not initialized. Call Init() function first")
	}
	eaaCtx.serviceInfo[serv.URN.ID+"."+serv.URN.Namespace] = serv
	return nil
}
