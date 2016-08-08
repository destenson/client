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
	"encoding/hex"
	"github.com/jonboulle/clockwork"
	"github.com/keybase/client/go/client"
	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol"
	"github.com/keybase/client/go/service"
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
	"strings"
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

type fakeTLF struct {
	id       string
	revision int
}

func newFakeTLF() *fakeTLF {
	return &fakeTLF{
		id:       newTLFId(),
		revision: 0,
	}
}

func (tlf *fakeTLF) nextRevision() int {
	tlf.revision++
	return tlf.revision
}

type backupKey struct {
	publicKID keybase1.KID
	secret    string
}

type rekeyTester struct {
	t              *testing.T
	serviceWrapper *serviceWrapper
	rekeyUI        *testRekeyUI
	fakeClock      clockwork.FakeClock
	rekeyClient    keybase1.RekeyClient
	userClient     keybase1.UserClient
	deviceKey      keybase1.PublicKey
	backupKeys     []backupKey
	fakeTLF        *fakeTLF
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
	rkt.serviceWrapper.start(3)
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
	keys, err := rkt.userClient.LoadMyPublicKeys(context.TODO(), 0)
	if err != nil {
		rkt.t.Fatalf("Failed to LoadMyPublicKeys: %s", err)
	}
	var backupKey backupKey
	backupKey.secret = signupUI.info.displayedPaperKey
	for _, key := range keys {
		switch key.DeviceType {
		case libkb.DeviceTypePaper:
			backupKey.publicKID = key.KID
		case libkb.DeviceTypeDesktop:
			rkt.deviceKey = key
		}
	}
	if len(rkt.deviceKey.KID) == 0 {
		rkt.t.Fatalf("Didn't get device key back for user")
	}
	if len(backupKey.publicKID) == 0 {
		rkt.t.Fatalf("Didn't get backup key back for user")
	}
	rkt.backupKeys = append(rkt.backupKeys, backupKey)
}

func (rkt *rekeyTester) startUIsAndClients() {
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
		rkt.userClient = keybase1.UserClient{Cli: cli}
		return nil
	}

	if err := launch(); err != nil {
		rkt.t.Fatalf("Failed to launch rekey UI: %s", err)
	}
}

func (rkt *rekeyTester) confirmNoRekeyUIActivity(hours int, force bool) {
	assertNoActivity := func(hour int) {
		select {
		case <-rkt.rekeyUI.refreshes:
			rkt.t.Errorf("Didn't expect any rekeys; got one at hour %d\n", hour)
		default:
		}
	}

	for i := 0; i < hours; i++ {
		assertNoActivity(i)
		rkt.fakeClock.Advance(time.Hour)
	}
	err := rkt.rekeyClient.RekeySync(context.TODO(), keybase1.RekeySyncArg{SessionID: 0, Force: force})
	if err != nil {
		rkt.t.Errorf("Error syncing rekey: %s", err)
	}
	assertNoActivity(hours + 1)
}

func newTLFId() string {
	var b []byte
	b, err := libkb.RandBytes(16)
	if err != nil {
		return ""
	}
	b[15] = 0x16
	return hex.EncodeToString(b)
}

func (rkt *rekeyTester) makeFullyKeyedHomeTLF() {
	kids := []keybase1.KID{rkt.deviceKey.KID}
	for _, bkp := range rkt.backupKeys {
		kids = append(kids, bkp.publicKID)
	}
	rkt.changeKeysOnHomeTLF(kids)
}

func (rkt *rekeyTester) changeKeysOnHomeTLF(kids []keybase1.KID) {

	var kidStrings []string

	for _, kid := range kids {
		kidStrings = append(kidStrings, string(kid))
	}

	// Use the global context from the service for making API calls
	// to the API server.
	g := rkt.serviceWrapper.tctx.G
	rkt.fakeTLF = newFakeTLF()
	apiArg := libkb.APIArg{
		Args: libkb.HTTPArgs{
			"tlfid":          libkb.S{Val: rkt.fakeTLF.id},
			"kids":           libkb.S{Val: strings.Join(kidStrings, ",")},
			"folderRevision": libkb.I{Val: rkt.fakeTLF.nextRevision()},
		},
		Endpoint:     "test/fake_home_tlf",
		NeedSession:  true,
		Contextified: libkb.NewContextified(g),
	}
	_, err := g.API.Post(apiArg)
	if err != nil {
		rkt.t.Fatalf("Failed to post fake TLF: %s", err)
	}
}

func (rkt *rekeyTester) bumpTLF(kid keybase1.KID) {

	// Use the global context from the service for making API calls
	// to the API server.
	g := rkt.serviceWrapper.tctx.G

	apiArg := libkb.APIArg{
		Args: libkb.HTTPArgs{
			"kid": libkb.S{Val: string(kid)},
		},
		Endpoint:     "kbfs/bump_rekey",
		NeedSession:  true,
		Contextified: libkb.NewContextified(g),
	}

	_, err := g.API.Post(apiArg)
	if err != nil {
		rkt.t.Fatalf("Failed to bump rekey to front of line: %s", err)
	}
}

func (rkt *rekeyTester) assertRekeyWindowPushed() {
	select {
	case <-rkt.rekeyUI.refreshes:
	case <-time.After(20 * time.Second):
		rkt.t.Fatalf("no gregor came in after 20s; something is broken")
	}
}

func (rkt *rekeyTester) consumeAllRekeyRefreshes() int {
	i := 0
	for {
		select {
		case <-rkt.rekeyUI.refreshes:
			i++
		default:
			break
		}
	}
	return i
}

func (rkt *rekeyTester) snoozeRekeyWindow() {
	_, err := rkt.rekeyClient.RekeyStatusFinish(context.TODO(), 0)
	if err != nil {
		rkt.t.Fatalf("Failed to finish rekey: %s\n", err)
	}
	// Our snooze should be 23 hours long, and should be resistent
	// to interrupts.
	rkt.confirmNoRekeyUIActivity(23, false)

	// In 2 more hours, we should get rereminded
	rkt.fakeClock.Advance(2 * time.Hour)

	// Now sync so that we're sure we get a full run through the loop.
	err = rkt.rekeyClient.RekeySync(context.TODO(), keybase1.RekeySyncArg{SessionID: 0, Force: false})
	if err != nil {
		rkt.t.Fatalf("Error syncing rekey: %s", err)
	}

	if rkt.consumeAllRekeyRefreshes() == 0 {
		rkt.t.Fatal("snoozed rekey window never came back")
	}
}

type testLoginUI struct {
	baseNullUI
	secret string
}

func (u *testLoginUI) DisplayPaperKeyPhrase(_ context.Context, arg keybase1.DisplayPaperKeyPhraseArg) error {
	u.secret = arg.Phrase
	return nil
}
func (u *testLoginUI) DisplayPrimaryPaperKey(context.Context, keybase1.DisplayPrimaryPaperKeyArg) error {
	return nil
}
func (u *testLoginUI) PromptRevokePaperKeys(context.Context, keybase1.PromptRevokePaperKeysArg) (bool, error) {
	return false, nil
}
func (u *testLoginUI) GetEmailOrUsername(context.Context, int) (string, error) {
	return "", nil
}

func (u *testLoginUI) GetLoginUI() libkb.LoginUI {
	return u
}

func (u *testLoginUI) GetSecretUI() libkb.SecretUI {
	return u
}

func (u *testLoginUI) GetPassphrase(p keybase1.GUIEntryArg, terminal *keybase1.SecretEntryArg) (res keybase1.GetPassphraseRes, err error) {
	return res, err
}

func (rkt *rekeyTester) findNewBackupKID(kids []keybase1.KID) (ret keybase1.KID) {
	for _, kidA := range kids {
		found := false
		for _, bkp := range rkt.backupKeys {
			if bkp.publicKID.Equal(kidA) {
				found = true
				break
			}
		}
		if !found {
			return kidA
		}
	}
	return ret
}

func (rkt *rekeyTester) generateNewBackupKey() {
	tctx := rkt.serviceWrapper.popClone()
	g := tctx.G
	loginUI := testLoginUI{}
	g.SetUI(&loginUI)
	paperGen := client.NewCmdPaperKeyRunner(g)
	if err := paperGen.Run(); err != nil {
		rkt.t.Fatal(err)
	}
	keys, err := rkt.userClient.LoadMyPublicKeys(context.TODO(), 0)
	if err != nil {
		rkt.t.Fatalf("Failed to LoadMyPublicKeys: %s", err)
	}
	var backupKey backupKey
	backupKey.secret = loginUI.secret

	var allBackupKIDs []keybase1.KID
	for _, key := range keys {
		switch key.DeviceType {
		case libkb.DeviceTypePaper:
			allBackupKIDs = append(allBackupKIDs, key.KID)
		}
	}

	kid := rkt.findNewBackupKID(allBackupKIDs)
	if kid.IsNil() {
		rkt.t.Fatalf("didn't find a new backup key!")
	}
	backupKey.publicKID = kid

	rkt.backupKeys = append(rkt.backupKeys, backupKey)
}

func TestRekey(t *testing.T) {
	rkt := newRekeyTester(t)
	rkt.setup("rekey")
	defer rkt.cleanup()

	rkt.startService()
	rkt.startUIsAndClients()

	// 1. Sign up a fake user with a device and paper key
	rkt.signupUserWithOneDevice()

	// 2. Make a private home TLF keyed only for the device key (not the paper)
	rkt.makeFullyKeyedHomeTLF()

	// 3. Assert no rekey activity
	rkt.confirmNoRekeyUIActivity(28, false)

	// 4. Now delegate to a new paper key
	rkt.generateNewBackupKey()

	// 5. wait for an incoming gregor notification for the new TLF,
	// since it's in a broken rekey state.
	// rkt.assertRekeyWindowPushed()

	// 6. Dismiss the window and assert it doesn't show up again for
	// another 24 hours.
	// rkt.snoozeRekeyWindow()

}
