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
	"github.com/keybase/client/go/client"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/service"
	"testing"
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
}

func newRekeyTester(t *testing.T) *rekeyTester {
	return &rekeyTester{
		t: t,
	}
}

func (rkt *rekeyTester) setup(nm string) {
	tctx := setupTest(rkt.t, nm)
	rkt.serviceWrapper = &serviceWrapper{tctx: tctx}
}

func (rkt *rekeyTester) startService() {
	rkt.serviceWrapper.start(1)
}

func (rkt *rekeyTester) cleanup() {
	rkt.serviceWrapper.tctx.Cleanup()
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

func TestRekey(t *testing.T) {
	rkt := newRekeyTester(t)
	rkt.setup("rekey")
	defer rkt.cleanup()

	rkt.startService()
	rkt.signupUserWithOneDevice()
}
