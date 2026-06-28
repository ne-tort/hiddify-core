package connectip

import "time"

func (c *UDPPacketConn) currentPayloadCeiling() int {
	if c.pmtuState == nil {
		return 1172
	}
	if v := c.pmtuState.CurrentPayload.Load(); v > 0 {
		return int(v)
	}
	c.pmtuState.Mu.Lock()
	if v := c.pmtuState.CurrentPayload.Load(); v > 0 {
		c.pmtuState.Mu.Unlock()
		return int(v)
	}
	c.pmtuState.CurrentPayload.Store(1172)
	c.pmtuState.Mu.Unlock()
	return 1172
}

func (c *UDPPacketConn) applyPTBToUDPPayload(ipPathMTU int, isIPv6 bool) int {
	if c.pmtuState == nil {
		return 1172
	}
	overhead := 28
	if isIPv6 {
		overhead = 48
	}
	udpMax := ipPathMTU - overhead
	if udpMax < 512 {
		udpMax = 512
	}
	c.pmtuState.Mu.Lock()
	cur := c.pmtuState.CurrentPayload.Load()
	if cur <= 0 {
		cur = 1172
		c.pmtuState.CurrentPayload.Store(cur)
	}
	if maxP := c.pmtuState.MaxPayload.Load(); maxP > 0 && int64(udpMax) > maxP {
		udpMax = int(maxP)
	}
	if int64(udpMax) < cur {
		c.pmtuState.CurrentPayload.Store(int64(udpMax))
		c.pmtuState.SuccessSinceDecrease.Store(0)
		cur = int64(udpMax)
	}
	c.pmtuState.Mu.Unlock()
	current := int(cur)
	obsEffectiveUDPPayload(current, "ptb_mtu_hint")
	return current
}

func (c *UDPPacketConn) decreasePayloadCeiling(reason string) int {
	if c.pmtuState == nil {
		return 1172
	}
	const pmtuMinus64DebounceMs = 80
	c.pmtuState.Mu.Lock()
	cur := c.pmtuState.CurrentPayload.Load()
	if cur <= 0 {
		cur = 1172
		c.pmtuState.CurrentPayload.Store(cur)
	}
	if reason == "ptb_feedback" {
		now := time.Now().UnixMilli()
		if last := c.pmtuState.LastMinus64UnixMilli.Load(); last != 0 && now-last < pmtuMinus64DebounceMs {
			c.pmtuState.Mu.Unlock()
			return int(cur)
		}
		c.pmtuState.LastMinus64UnixMilli.Store(now)
	}
	minP := c.pmtuState.MinPayload.Load()
	next := cur - 64
	if next < minP {
		next = minP
	}
	if next < cur {
		c.pmtuState.CurrentPayload.Store(next)
		c.pmtuState.SuccessSinceDecrease.Store(0)
		cur = next
	}
	c.pmtuState.Mu.Unlock()
	current := int(cur)
	obsEffectiveUDPPayload(current, reason)
	return current
}

func (c *UDPPacketConn) maybeRecoverPayloadCeiling() int {
	if c.pmtuState == nil {
		return 1172
	}
	const recoverySuccessWindow = 256
	cur := c.pmtuState.CurrentPayload.Load()
	maxP := c.pmtuState.MaxPayload.Load()
	if cur <= 0 {
		c.pmtuState.Mu.Lock()
		cur = c.pmtuState.CurrentPayload.Load()
		if cur <= 0 {
			cur = 1172
			c.pmtuState.CurrentPayload.Store(cur)
		}
		maxP = c.pmtuState.MaxPayload.Load()
		c.pmtuState.Mu.Unlock()
	}
	n := c.pmtuState.SuccessSinceDecrease.Add(1)
	if maxP > 0 && cur >= maxP {
		return int(cur)
	}
	if n < recoverySuccessWindow {
		return int(cur)
	}
	c.pmtuState.Mu.Lock()
	cur = c.pmtuState.CurrentPayload.Load()
	maxP = c.pmtuState.MaxPayload.Load()
	if maxP > 0 && cur >= maxP {
		c.pmtuState.Mu.Unlock()
		return int(cur)
	}
	if c.pmtuState.SuccessSinceDecrease.Load() < recoverySuccessWindow {
		c.pmtuState.Mu.Unlock()
		return int(cur)
	}
	next := cur + 16
	if maxP > 0 && next > maxP {
		next = maxP
	}
	c.pmtuState.CurrentPayload.Store(next)
	c.pmtuState.SuccessSinceDecrease.Store(0)
	c.pmtuState.Mu.Unlock()
	obsEffectiveUDPPayload(int(next), "recovery_increase")
	return int(next)
}
