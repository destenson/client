package systests

// Strategy:
//
//   1. Sign up a fake user with a device and paper key
//   2. Assert no rekey activity
//   3. Call the test/fake_home_tlf endpoint to fake a TLF that's only
//      keyed for the device key (and not the paper key).
//   4. Assert that we get a rekey harassment window.
//   5. Dismiss the window and assert it doesn't show up again for
//      another 24 hours.
//   6. Enter the paper key, and fast-forward a bunch of time. Assert
//      we don't get harassed, since now all of our devices are online.
//   7. Provision new device, but don't change the keying of the TLF.
//   8. Assert that the window shows up right away.
//   9. Snooze it.
//  10. Assert that the snooze lasts for ~24 hours.
//  11. Logout and Login. Assert we get the popup right away.
//  12. Snooze it and assert snooze lasts for ~24 hours.
//  13. Have the window open.
//  14. Call the test/fake_home_tlf endpoint to fully rekey the TLF.
//  15. Assert the window is dismissed within ~1 minute.
//  16. Assert that our gregor queue is empty for this category.
//

import (
	"github.com/jonboulle/clockwork"
	"github.com/keybase/client/go/client"
	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol"
	"github.com/keybase/client/go/service"
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
	"testing"
	"time"
)

type serviceWrapper struct {
	tctx    *libkb.TestContext
	clones  []*libkb.TestContext
	stopCh  chan error
	service *service.Service
}

func (d *serviceWrapper) start(numClones int) {
	for i := 0; i < numClones; i++ {
		d.clones = append(d.clones, cloneContext(d.tctx))
	}
	d.stopCh = make(chan error)
	svc := service.NewService(d.tctx.G, false)
	d.service = svc
	startCh := svc.GetStartChannel()
	go func() {
		d.stopCh <- svc.Run()
	}()
	<-startCh
}

func (d *serviceWrapper) stop() error {
	return <-d.stopCh
}

func (d *serviceWrapper) popClone() *libkb.TestContext {
	if len(d.clones) == 0 {
		panic("ran out of cloned environments")
	}
	ret := d.clones[0]
	d.clones = d.clones[1:]
	return ret
}

type rekeyTester struct {
	t              *testing.T
	serviceWrapper *serviceWrapper
	rekeyUI        *testRekeyUI
	fakeClock      clockwork.FakeClock
	rekeyClient    keybase1.RekeyClient
}

func newRekeyTester(t *testing.T) *rekeyTester {
	return &rekeyTester{
		t: t,
	}
}

func (rkt *rekeyTester) setup(nm string) {
	tctx := setupTest(rkt.t, nm)
	fakeClock := clockwork.NewFakeClockAt(time.Now())
	rkt.fakeClock = fakeClock
	tctx.G.SetClock(fakeClock)
	rkt.serviceWrapper = &serviceWrapper{tctx: tctx}
}

func (rkt *rekeyTester) startService() {
	rkt.serviceWrapper.start(2)
}

func (rkt *rekeyTester) cleanup() {
	rkt.serviceWrapper.tctx.Cleanup()
}

type testRekeyUI struct {
	sessionID int
	refreshes chan keybase1.RefreshArg
}

func (ui *testRekeyUI) DelegateRekeyUI(_ context.Context) (int, error) {
	ui.sessionID++
	ret := ui.sessionID
	return ret, nil
}

func (ui *testRekeyUI) Refresh(_ context.Context, arg keybase1.RefreshArg) error {
	ui.refreshes <- arg
	return nil
}

func newTestRekeyUI() *testRekeyUI {
	return &testRekeyUI{
		sessionID: 0,
		refreshes: make(chan keybase1.RefreshArg, 1000),
	}
}

func (rkt *rekeyTester) signupUserWithOneDevice() {
	userInfo := randomUser("rekey")
	tctx := rkt.serviceWrapper.popClone()
	g := tctx.G
	signupUI := signupUI{
		info:         userInfo,
		Contextified: libkb.NewContextified(g),
	}
	g.SetUI(&signupUI)
	signup := client.NewCmdSignupRunner(g)
	signup.SetTest()
	if err := signup.Run(); err != nil {
		rkt.t.Fatal(err)
	}
	rkt.t.Logf("signed up %s", userInfo.username)
}

func (rkt *rekeyTester) startRekeyUI() {
	ui := newTestRekeyUI()
	rkt.rekeyUI = ui
	tctx := rkt.serviceWrapper.popClone()
	g := tctx.G

	launch := func() error {
		cli, xp, err := client.GetRPCClientWithContext(g)
		if err != nil {
			return err
		}
		srv := rpc.NewServer(xp, nil)
		if err = srv.Register(keybase1.RekeyUIProtocol(ui)); err != nil {
			return err
		}
		ncli := keybase1.DelegateUiCtlClient{Cli: cli}
		if err = ncli.RegisterRekeyUI(context.TODO()); err != nil {
			return err
		}
		rkt.rekeyClient = keybase1.RekeyClient{Cli: cli}
		return nil
	}

	if err := launch(); err != nil {
		rkt.t.Fatalf("Failed to launch rekey UI: %s", err)
	}
}

func (rkt *rekeyTester) confirmNoRekeyUIActivity() {
	assertNoActivity := func(hour int) {
		select {
		case <-rkt.rekeyUI.refreshes:
			rkt.t.Errorf("Didn't expect any rekeys; got one at hour %d\n", hour)
		default:
		}
	}

	for i := 0; i < 28; i++ {
		assertNoActivity(i)
		rkt.fakeClock.Advance(time.Hour)
	}
	err := rkt.rekeyClient.Sync(context.TODO(), 0)
	if err != nil {
		rkt.t.Errorf("Error syncing rekey: %s", err)
	}
	assertNoActivity(29)
}

func TestRekey(t *testing.T) {
	rkt := newRekeyTester(t)
	rkt.setup("rekey")
	defer rkt.cleanup()

	rkt.startService()
	rkt.startRekeyUI()
	rkt.signupUserWithOneDevice()
	rkt.confirmNoRekeyUIActivity()
}
