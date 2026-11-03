//go:build linux && amd64

package core

import "net"

func trackedConnOf(conn net.Conn) *trackedHandoffConn {
	switch c := conn.(type) {
	case *trackedHandoffConn:
		return c
	case *aead13Conn:
		tracked, _ := c.conn.(*trackedHandoffConn)
		return tracked
	}
	return nil
}

func (c *trackedHandoffConn) retainSlots() bool {
	c.holdMu.Lock()
	defer c.holdMu.Unlock()
	if c.closed {
		return false
	}
	c.holds++
	return true
}

func (c *trackedHandoffConn) releaseHold() {
	c.holdMu.Lock()
	c.holds--
	release := c.holds == 0 && c.closed
	c.holdMu.Unlock()
	if release {
		c.releaseSlots()
	}
}

func (c *trackedHandoffConn) finishClose() {
	c.holdMu.Lock()
	c.closed = true
	release := c.holds == 0
	c.holdMu.Unlock()
	if release {
		c.releaseSlots()
	}
}

func (c *trackedHandoffConn) releaseSlots() {
	if c.server != nil {
		c.server.untrackHandoffConn(c)
	}
	if c.onClose != nil {
		c.onClose()
	}
}
