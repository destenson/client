// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package service

import (
	"github.com/keybase/client/go/libkb"
	// keybase1 "github.com/keybase/client/go/protocol"
	gregor "github.com/keybase/gregor"
	gregor1 "github.com/keybase/gregor/protocol/gregor1"
	context "golang.org/x/net/context"
	"time"
)

type rekeyMaster struct {
	libkb.Contextified
	interruptCh chan rekeyInterrupt
}

func newRekeyMaster(g *libkb.GlobalContext) *rekeyMaster {
	return &rekeyMaster{
		Contextified: libkb.NewContextified(g),
		interruptCh:  make(chan rekeyInterrupt),
	}
}

func (r *rekeyMaster) IsAlive() bool {
	return true
}
func (r *rekeyMaster) Name() string {
	return "rekeyMaster"
}

func (r *rekeyMaster) Create(ctx context.Context, cli gregor1.IncomingInterface, category string, ibm gregor.Item) (bool, error) {
	switch category {
	case "kbfs_tlf_rekey_needed":
		return true, r.handleGregorCreation()
	}
	return true, nil
}

func (r *rekeyMaster) handleGregorCreation() error {
	return nil
}

func (r *rekeyMaster) Dismiss(ctx context.Context, cli gregor1.IncomingInterface, category string, ibm gregor.Item) (bool, error) {
	switch category {
	case "kbfs_tlf_rekey_needed":
		return true, r.handleGregorDismissal()
	}
	return true, nil
}

func (r *rekeyMaster) handleGregorDismissal() error {
	return nil
}

func (r *rekeyMaster) gregorHandler() *rekeyMaster {
	return r
}

type rekeyInterrupt int

const (
	rekeyInterruptNone    rekeyInterrupt = 0
	rekeyInterruptTimeout rekeyInterrupt = 1
)

func (r *rekeyMaster) runOnce(ri rekeyInterrupt) time.Duration {
	return 24 * time.Hour
}

func (r *rekeyMaster) mainLoop() {
	// By default, check in once a day
	var it rekeyInterrupt
	for {
		timeout := r.runOnce(it)
		select {
		case it = <-r.interruptCh:
			break
		case <-r.G().Clock().After(timeout):
			it = rekeyInterruptTimeout
		}
	}
}
