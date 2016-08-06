// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package service

import (
	"fmt"
	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol"
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

func (r *rekeyMaster) Start() {
	go r.mainLoop()
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
	r.interruptCh <- rekeyInterruptCreation
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
	r.interruptCh <- rekeyInterruptDismissal
	return nil
}

func (r *rekeyMaster) gregorHandler() *rekeyMaster {
	return r
}

func (r *rekeyMaster) Logout() {
	r.interruptCh <- rekeyInterruptLogout
}

func (r *rekeyMaster) Login() {
	r.interruptCh <- rekeyInterruptLogin
}

type rekeyInterrupt int

const (
	rekeyInterruptNone      rekeyInterrupt = 0
	rekeyInterruptTimeout   rekeyInterrupt = 1
	rekeyInterruptCreation  rekeyInterrupt = 2
	rekeyInterruptDismissal rekeyInterrupt = 3
	rekeyInterruptLogout    rekeyInterrupt = 4
	rekeyInterruptLogin     rekeyInterrupt = 5
)
const (
	rekeyTimeoutBackground      = 24 * time.Hour
	rekeyTimeoutAPIError        = 3 * time.Minute
	rekeyTimeoutLoadMeError     = 3 * time.Minute
	rekeyTimeoutDeviceLoadError = 3 * time.Minute
	rekeyTimeoutActive          = 1 * time.Minute
)

type rekeyQueryResult struct {
	Status     libkb.AppStatus     `json:"status"`
	ProblemSet keybase1.ProblemSet `json:"problem_set"`
}

func (r *rekeyQueryResult) GetAppStatus() *libkb.AppStatus {
	return &r.Status
}

func (r *rekeyMaster) queryAPIServer() (keybase1.ProblemSet, error) {
	args := libkb.HTTPArgs{
		"clear": libkb.B{Val: true},
	}
	var tmp rekeyQueryResult
	// We have to post to use the clear=true feature
	err := r.G().API.PostDecode(libkb.APIArg{
		Contextified: libkb.NewContextified(r.G()),
		Endpoint:     "kbfs/problem_sets",
		NeedSession:  true,
		Args:         args,
	}, &tmp)
	return tmp.ProblemSet, err
}

func (r *rekeyMaster) runOnce(ri rekeyInterrupt) (ret time.Duration, err error) {
	defer r.G().Trace(fmt.Sprintf("rekeyMaster#runOnce(%d)", ri), func() error { return err })()

	// compute which folders if any have problems
	ret, _, err = r.computeProblems()

	// TODO: act upon the problems by spawning or refreshing the rekeyUI

	return ret, err
}

func (r *rekeyMaster) computeProblems() (nextWait time.Duration, problemsAndDevices *keybase1.ProblemSetDevices, err error) {
	defer r.G().Trace("rekeyMaster#computeProblems", func() error { return err })()

	if loggedIn, _, _ := libkb.IsLoggedIn(r.G(), nil); !loggedIn {
		r.G().Log.Debug("| not logged in")
		nextWait = rekeyTimeoutBackground
		return nextWait, nil, err
	}

	var problems keybase1.ProblemSet
	problems, err = r.queryAPIServer()
	if err != nil {
		nextWait = rekeyTimeoutAPIError
		r.G().Log.Debug("| snoozing rekeyMaster for %ds on API error", nextWait)
		return nextWait, nil, err
	}

	if len(problems.Tlfs) == 0 {
		r.G().Log.Debug("| no problem TLFs found")
		nextWait = rekeyTimeoutBackground
		return nextWait, nil, err
	}

	var me *libkb.User
	me, err = libkb.LoadMe(libkb.NewLoadUserArg(r.G()))
	if err != nil {
		nextWait = rekeyTimeoutLoadMeError
		r.G().Log.Debug("| snoozing rekeyMaster for %ds on LoadMe error", nextWait)
		return nextWait, nil, err
	}

	if r.currentDeviceSolvesProblemSet(me, problems) {
		nextWait = rekeyTimeoutBackground
		r.G().Log.Debug("| snoozing rekeyMaster since current device can rekey all")
		return nextWait, nil, err
	}

	var tmp keybase1.ProblemSetDevices
	tmp, err = newProblemSetDevices(me, problems)
	if err != nil {
		nextWait = rekeyTimeoutDeviceLoadError
		r.G().Log.Debug("| hit error in loading devices")
		return nextWait, nil, err
	}

	nextWait = rekeyTimeoutActive
	return nextWait, &tmp, err
}

// currentDeviceSolvesProblemSet returns true if the current device can fix all
// of the folders in the ProblemSet.
func (r *rekeyMaster) currentDeviceSolvesProblemSet(me *libkb.User, ps keybase1.ProblemSet) (ret bool) {
	r.G().Log.Debug("+ currentDeviceSolvesProblemSet")
	defer func() {
		r.G().Log.Debug("- currentDeviceSolvesProblemSet -> %v\n", ret)
	}()

	var paperKey libkb.GenericKey
	deviceKey, err := me.GetDeviceSubkey()
	if err != nil {
		r.G().Log.Info("| Problem getting device subkey: %s\n", err)
		return ret
	}

	err = r.G().LoginState().Account(func(a *libkb.Account) {
		paperKey = a.GetUnlockedPaperEncKey()
	}, "currentDeviceSolvesProblemSet")

	// We can continue though, so no need to error out
	if err != nil {
		r.G().Log.Info("| Error getting paper key: %s\n", err)
		err = nil
	}

	for _, tlf := range ps.Tlfs {
		if !keysSolveProblemTLF([]libkb.GenericKey{deviceKey, paperKey}, tlf) {
			r.G().Log.Debug("| Doesn't solve problem TLF: %s (%s)\n", tlf.Tlf.Name, tlf.Tlf.Id)
			return ret
		}
	}
	ret = true
	return ret
}

func (r *rekeyMaster) mainLoop() {
	// By default, check in once a day
	var it rekeyInterrupt
	for {
		timeout, _ := r.runOnce(it)
		select {
		case it = <-r.interruptCh:
			break
		case <-r.G().Clock().After(timeout):
			it = rekeyInterruptTimeout
		}
	}
}
