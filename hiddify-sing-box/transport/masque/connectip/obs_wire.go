package connectip

// CounterObsHooks returns Obs hooks that update CONNECT-IP observability counters.
func CounterObsHooks() Obs {
	return Obs{
		EventsEnabled: obsEventsEnabledFromEnv,
		OnPacketRx: func(n int) {
			rxSeq := obsCounters.packetRxTotal.Add(1)
			obsCounters.bytesRxTotal.Add(uint64(n))
			if !obsEventsEnabled() {
				return
			}
			if obsCounters.firstRxMarkerEmitted.CompareAndSwap(0, 1) {
				EmitObservabilityEvent("first_packet_rx")
			}
			maybeEmitActiveSnapshot(rxSeq)
		},
		OnPacketTx: func(ipLen int) {
			txSeq := obsCounters.packetTxTotal.Add(1)
			obsCounters.bytesTxTotal.Add(uint64(ipLen))
			if !obsEventsEnabled() {
				return
			}
			if obsCounters.firstTxMarkerEmitted.CompareAndSwap(0, 1) {
				EmitObservabilityEvent("first_packet_tx")
			}
			maybeEmitActiveSnapshot(txSeq)
		},
		OnPacketReadExit: func(err error) {
			obsCounters.packetReadExitTotal.Add(1)
			IncReadDropReason(ClassifyWriteError(err))
			if obsEventsEnabled() {
				EmitObservabilityEvent("packet_read_exit")
			}
		},
		OnPacketWriteFail: func(err error, ceiling bool) {
			obsCounters.packetWriteFailTotal.Add(1)
			if ceiling {
				IncWriteFailReason("ceiling_reject")
				if obsEventsEnabled() {
					EmitObservabilityEvent("packet_write_fail_ceiling")
				}
				return
			}
			IncWriteFailReason(ClassifyWriteError(err))
			if obsEventsEnabled() {
				EmitObservabilityEvent("packet_write_fail")
			}
		},
		OnPacketPTBRx: func() {
			obsCounters.ptbRxTotal.Add(1)
			if obsEventsEnabled() {
				maybeEmitPTBObs("packet_ptb_rx")
			}
		},
		OnReadInject: func() {
			obsCounters.netstackReadInjectTotal.Add(1)
		},
		OnReadDropInvalid: func() {
			obsCounters.netstackReadDropInvalidTotal.Add(1)
			IncReadDropReason("invalid_ip_version")
		},
		OnWriteDequeued: func() {
			obsCounters.netstackWriteDequeuedTotal.Add(1)
		},
		OnWriteAttempt: func() {
			obsCounters.netstackWriteAttemptTotal.Add(1)
		},
		OnWriteSuccess: func() {
			obsCounters.netstackWriteSuccessTotal.Add(1)
		},
		OnWriteFailReason: IncWriteFailReason,
		OnSessionReset:    IncSessionReset,
		OnReadDropReason:  IncReadDropReason,
		OnEngineDrop:      IncEngineDropReason,
		OnEngineIngress: func() {
			obsCounters.engineIngressTotal.Add(1)
		},
		OnEngineClassified: func() {
			obsCounters.engineClassifiedTotal.Add(1)
		},
		OnEngineICMPFeedback: func() {
			obsCounters.engineICMPFeedbackTotal.Add(1)
		},
		OnBridgeWriteEnter: func() {
			obsCounters.bridgeWriteEnterTotal.Add(1)
		},
		OnBridgeUDPTXAttempt: func() {
			obsCounters.bridgeUDPTXAttemptTotal.Add(1)
		},
		OnBridgeWriteChunk: func() {
			obsCounters.bridgeWriteChunkTotal.Add(1)
		},
		OnBridgeBuild: func() {
			obsCounters.bridgeBuildTotal.Add(1)
		},
		OnBridgeWriteOK: func() {
			obsCounters.bridgeWriteOkTotal.Add(1)
		},
		OnBridgeWriteErr: func(reason string) {
			obsCounters.bridgeWriteErrTotal.Add(1)
			obsCounters.mu.Lock()
			obsCounters.bridgeWriteErrByReason[reason]++
			obsCounters.mu.Unlock()
		},
		OnEffectiveUDPPayload: SetEngineEffectiveUDPPayload,
		ClassifyWriteError:    ClassifyWriteError,
	}
}
