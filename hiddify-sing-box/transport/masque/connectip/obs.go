package connectip

import (
	"os"
	"strings"
)

// Obs hooks optional CONNECT-IP netstack counters (wired from transport/masque).
type Obs struct {
	EventsEnabled              func() bool
	OnReadInject               func()
	OnReadDropInvalid          func()
	OnWriteDequeued            func()
	OnWriteAttempt             func()
	OnWriteSuccess             func()
	OnWriteFailReason          func(reason string)
	OnSessionReset             func(reason string)
	OnReadDropReason           func(reason string)
	OnEngineDrop               func(reason string)
	OnIngressObsEvent          func(name string)
	OnEngineIngress            func()
	OnEngineClassified         func()
	OnEngineICMPFeedback       func()
	OnBridgeWriteEnter         func()
	OnBridgeUDPTXAttempt       func()
	OnBridgeWriteChunk         func()
	OnBridgeBuild              func()
	OnBridgeWriteOK            func()
	OnBridgeWriteErr           func(reason string)
	OnEffectiveUDPPayload      func(payload int, reason string)
	OnPacketRx                 func(n int)
	OnPacketTx                 func(ipLen int)
	OnPacketReadExit           func(err error)
	OnPacketWriteFail          func(err error, ceiling bool)
	OnPacketPTBRx              func()
	ClassifyWriteError         func(err error) string
}

var obs Obs

// SetObs installs observability hooks (called from transport/masque init).
func SetObs(o Obs) {
	obs = o
}

func obsEventsEnabledFromEnv() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_OBS")) == "1"
}

func obsEventsEnabled() bool {
	if obs.EventsEnabled != nil {
		return obs.EventsEnabled()
	}
	return obsEventsEnabledFromEnv()
}

func obsReadInject() {
	if obs.OnReadInject != nil {
		obs.OnReadInject()
	}
}

func obsReadDropInvalid() {
	if obs.OnReadDropInvalid != nil {
		obs.OnReadDropInvalid()
	}
}

func obsWriteDequeued() {
	if obs.OnWriteDequeued != nil {
		obs.OnWriteDequeued()
	}
}

func obsWriteAttempt() {
	if obs.OnWriteAttempt != nil {
		obs.OnWriteAttempt()
	}
}

func obsWriteSuccess() {
	if obs.OnWriteSuccess != nil {
		obs.OnWriteSuccess()
	}
}

func obsWriteFailReason(reason string) {
	if obs.OnWriteFailReason != nil {
		obs.OnWriteFailReason(reason)
	}
}

func obsSessionReset(reason string) {
	if obs.OnSessionReset != nil {
		obs.OnSessionReset(reason)
	}
}

func obsReadDropReason(reason string) {
	if obs.OnReadDropReason != nil {
		obs.OnReadDropReason(reason)
	}
}

func obsEngineDrop(reason string) {
	if obs.OnEngineDrop != nil {
		obs.OnEngineDrop(reason)
	}
}

func obsIngressEvent(name string) {
	if obs.OnIngressObsEvent != nil {
		obs.OnIngressObsEvent(name)
	}
}

func obsEngineIngress() {
	if obs.OnEngineIngress != nil {
		obs.OnEngineIngress()
	}
}

func obsEngineClassified() {
	if obs.OnEngineClassified != nil {
		obs.OnEngineClassified()
	}
}

func obsEngineICMPFeedback() {
	if obs.OnEngineICMPFeedback != nil {
		obs.OnEngineICMPFeedback()
	}
}

func obsBridgeWriteEnter() {
	if obs.OnBridgeWriteEnter != nil {
		obs.OnBridgeWriteEnter()
	}
}

func obsBridgeUDPTXAttempt() {
	if obs.OnBridgeUDPTXAttempt != nil {
		obs.OnBridgeUDPTXAttempt()
	}
}

func obsBridgeWriteChunk() {
	if obs.OnBridgeWriteChunk != nil {
		obs.OnBridgeWriteChunk()
	}
}

func obsBridgeBuild() {
	if obs.OnBridgeBuild != nil {
		obs.OnBridgeBuild()
	}
}

func obsBridgeWriteOK() {
	if obs.OnBridgeWriteOK != nil {
		obs.OnBridgeWriteOK()
	}
}

func obsBridgeWriteErr(reason string) {
	if obs.OnBridgeWriteErr != nil {
		obs.OnBridgeWriteErr(reason)
	}
}

func obsEffectiveUDPPayload(payload int, reason string) {
	if obs.OnEffectiveUDPPayload != nil {
		obs.OnEffectiveUDPPayload(payload, reason)
	}
}

func obsClassifyWriteError(err error) string {
	if obs.ClassifyWriteError != nil {
		return obs.ClassifyWriteError(err)
	}
	return "other"
}
