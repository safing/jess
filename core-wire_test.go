package jess

import (
	"fmt"
	"testing"
	"time"

	"github.com/safing/portbase/container"
)

func TestWire(t *testing.T) {
	wireReKeyAfterMsgs = 100

	// current suites recommendation
	testWireCorrespondence(t, getSuite(t, SuiteWire), testData1)
	testWireCorrespondence(t, getSuite(t, SuiteWire), testData2)

	// older suites
	// testWireCorrespondence(t, getSuite(t, SuiteWireV1), testData1)
	// testWireCorrespondence(t, getSuite(t, SuiteWireV1), testData2)
}

func testWireCorrespondence(t *testing.T, suite *Suite, testData string) {
	wtr := &wireTestRange{t: t}
	wtr.init(suite, testData)
	fmt.Printf("\n\nsimulating %v\n", suite.ID)
	fmt.Println("two dots are one packet send+recv:")

	fmt.Println("\nclient ->")
	wtr.clientSend()

	fmt.Println("\n-> server")
	wtr.serverRecv()

	wtr.clientSend()
	wtr.serverRecv()

	fmt.Println("\n<- server")
	wtr.serverSend()

	fmt.Println("\nclient <-")
	wtr.clientRecv()

	for i := 0; i < 100; i++ {
		// up
		wtr.clientSend()
		wtr.serverRecv()
		wtr.clientSend()
		wtr.serverRecv()
		// down
		wtr.serverSend()
		wtr.clientRecv()
		wtr.serverSend()
		wtr.clientRecv()
	}

	for i := 0; i < 100; i++ {
		// up
		wtr.clientSend()
		wtr.serverRecv()

		// down
		wtr.serverSend()
		wtr.clientRecv()
		wtr.serverSend()
		wtr.clientRecv()
		wtr.serverSend()
		wtr.clientRecv()
	}

	wtr.endTime = time.Now()
	overhead := ((float64(wtr.bytesOnWire) / float64(wtr.bytesTransferred)) - 1) * 100
	duration := wtr.endTime.Sub(wtr.startTime)
	t.Logf(
		"%v tested: msgsize=%d, rekey every %d msgs, %d msgs, %d bytes, +%f%% overhead, %s, %s per msg, %f Mbit/s",
		wtr.suite.ID,
		len(testData),
		wireReKeyAfterMsgs,
		wtr.msgsTransferred,
		wtr.bytesTransferred,
		overhead,
		duration,
		time.Duration(duration.Nanoseconds()/int64(wtr.msgsTransferred)),
		float64(wtr.bytesTransferred*8/1000000)/duration.Seconds(),
	)
}

// TODO
// func benchmarkWireCorrespondence(t *testing.T, toolIDs []string) {
// }

type wireTestRange struct {
	t        *testing.T
	suite    *Suite
	testData string

	client *Session
	server *Session

	clientToServer chan *container.Container
	serverToClient chan *container.Container

	msgsTransferred  int
	bytesTransferred int
	bytesOnWire      int
	startTime        time.Time
	endTime          time.Time
}

func (wtr *wireTestRange) init(suite *Suite, testData string) (detectedInvalid bool) {
	wtr.suite = suite

	e, err := setupEnvelopeAndTrustStore(wtr.t, wtr.suite)
	if err != nil {
		wtr.t.Fatalf("%s failed to setup envelope: %s", wtr.suite.ID, err)
		return false
	}
	if e == nil {
		return true
	}

	wtr.client, err = e.WireCorrespondence(testTrustStore)
	if err != nil {
		wtr.t.Fatalf("%s failed to init client session: %s", wtr.suite.ID, err)
	}

	// setup and reset
	wtr.testData = testData
	wtr.server = nil
	wtr.clientToServer = make(chan *container.Container, 1000)
	wtr.serverToClient = make(chan *container.Container, 1000)
	wtr.msgsTransferred = 0
	wtr.bytesTransferred = 0
	wtr.bytesOnWire = 0
	wtr.startTime = time.Now()
	wtr.endTime = time.Time{}

	return false
}

func (wtr *wireTestRange) clientSend() {
	letter, err := wtr.client.Close([]byte(wtr.testData))
	if err != nil {
		wtr.t.Fatalf("%s failed to close: %s", wtr.suite.ID, err)
	}

	wireData, err := letter.ToWire()
	if err != nil {
		wtr.t.Fatalf("%s failed to serialize to wire: %s", wtr.suite.ID, err)
	}

	select {
	case wtr.clientToServer <- wireData:
	default:
		wtr.t.Fatalf("%s could not send to server", wtr.suite.ID)
	}

	fmt.Print(".")
}

func (wtr *wireTestRange) serverRecv() {
	select {
	case wireData := <-wtr.clientToServer:
		wtr.msgsTransferred++
		wtr.bytesOnWire += wireData.Length()

		letter, err := LetterFromWire(wireData)
		if err != nil {
			wtr.t.Fatalf("%s failed to parse initial wired letter: %s", wtr.suite.ID, err)
		}

		if wtr.server == nil {
			wtr.server, err = letter.WireCorrespondence(testTrustStore)
			if err != nil {
				wtr.t.Fatalf("%s failed to init server session: %s", wtr.suite.ID, err)
			}
		}

		origData, err := wtr.server.Open(letter)
		if err != nil {
			wtr.t.Fatalf("%s failed to open: %s", wtr.suite.ID, err)
		}
		wtr.bytesTransferred += len(origData)

		if string(origData) != wtr.testData {
			wtr.t.Fatalf("%s testdata mismatch", wtr.suite.ID)
		}
	default:
		wtr.t.Fatalf("%s could not recv from client", wtr.suite.ID)
	}

	fmt.Print(".")
}

func (wtr *wireTestRange) serverSend() {
	letter, err := wtr.server.Close([]byte(wtr.testData))
	if err != nil {
		wtr.t.Fatalf("%s failed to close: %s", wtr.suite.ID, err)
	}

	wireData, err := letter.ToWire()
	if err != nil {
		wtr.t.Fatalf("%s failed to serialize to wire: %s", wtr.suite.ID, err)
	}

	select {
	case wtr.serverToClient <- wireData:
	default:
		wtr.t.Fatalf("%s could not send to client", wtr.suite.ID)
	}

	fmt.Print(".")
}

func (wtr *wireTestRange) clientRecv() {
	select {
	case wireData := <-wtr.serverToClient:
		wtr.msgsTransferred++
		wtr.bytesOnWire += wireData.Length()

		letter, err := LetterFromWire(wireData)
		if err != nil {
			wtr.t.Fatalf("%s failed to parse initial wired letter: %s", wtr.suite.ID, err)
		}

		origData, err := wtr.client.Open(letter)
		if err != nil {
			wtr.t.Fatalf("%s failed to open: %s", wtr.suite.ID, err)
		}
		wtr.bytesTransferred += len(origData)

		if string(origData) != wtr.testData {
			wtr.t.Fatalf("%s testdata mismatch", wtr.suite.ID)
		}
	default:
		wtr.t.Fatalf("%s could not recv from server", wtr.suite.ID)
	}

	fmt.Print(".")
}
