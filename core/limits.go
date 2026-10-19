//go:build linux && amd64

package core

import (
	"errors"
	"fmt"
	"time"
)

const (
	limitDefaultMaxConns         = 8192
	limitDefaultMaxConnsPerIP    = 20
	limitDefaultMaxBodySize      = 4 << 20
	limitDefaultMaxHeaderSize    = 8192
	limitDefaultReadTimeout      = 30 * time.Second
	limitDefaultWriteTimeout     = 30 * time.Second
	limitDefaultIdleTimeout      = 120 * time.Second
	limitDefaultHandshakeTimeout = 30 * time.Second
)

var ErrInvalidLimits = errors.New("core: invalid limits")

type Limits struct {
	MaxConns          int64
	MaxConnsPerIP     int64
	MaxBodySize       int64
	StreamBodyAbove   int64
	MaxHeaderSize     int
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	HandshakeTimeout  time.Duration
}

func limitsFromConfig(cfg *Config) Limits {
	return Limits{
		MaxConns:          cfg.MaxConns,
		MaxConnsPerIP:     cfg.MaxConnsPerIP,
		MaxBodySize:       cfg.MaxBodySize,
		StreamBodyAbove:   cfg.StreamBodyAbove,
		MaxHeaderSize:     cfg.MaxHeaderSize,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		HandshakeTimeout:  cfg.HandshakeTimeout,
	}
}

func (l Limits) writeTo(cfg *Config) {
	cfg.MaxConns = l.MaxConns
	cfg.MaxConnsPerIP = l.MaxConnsPerIP
	cfg.MaxBodySize = l.MaxBodySize
	cfg.StreamBodyAbove = l.StreamBodyAbove
	cfg.MaxHeaderSize = l.MaxHeaderSize
	cfg.ReadTimeout = l.ReadTimeout
	cfg.ReadHeaderTimeout = l.ReadHeaderTimeout
	cfg.WriteTimeout = l.WriteTimeout
	cfg.IdleTimeout = l.IdleTimeout
	cfg.HandshakeTimeout = l.HandshakeTimeout
}

func (l Limits) withDefaults() Limits {
	if l.MaxConns == 0 {
		l.MaxConns = limitDefaultMaxConns
	}
	if l.MaxConnsPerIP == 0 {
		l.MaxConnsPerIP = limitDefaultMaxConnsPerIP
	}
	if l.MaxBodySize == 0 {
		l.MaxBodySize = limitDefaultMaxBodySize
	}
	if l.MaxHeaderSize == 0 {
		l.MaxHeaderSize = limitDefaultMaxHeaderSize
	}
	if l.ReadTimeout == 0 {
		l.ReadTimeout = limitDefaultReadTimeout
	}
	if l.WriteTimeout == 0 {
		l.WriteTimeout = limitDefaultWriteTimeout
	}
	if l.IdleTimeout == 0 {
		l.IdleTimeout = limitDefaultIdleTimeout
	}
	if l.HandshakeTimeout == 0 {
		l.HandshakeTimeout = limitDefaultHandshakeTimeout
	}
	return l
}

func (l Limits) validate() error {
	if l.MaxHeaderSize < 0 {
		return fmt.Errorf("%w: MaxHeaderSize must not be negative", ErrInvalidLimits)
	}
	if l.StreamBodyAbove < 0 {
		return fmt.Errorf("%w: StreamBodyAbove must not be negative", ErrInvalidLimits)
	}
	return nil
}

func (l *Limits) headerTimeout() time.Duration {
	return optionalDuration(l.ReadHeaderTimeout, optionalDuration(l.ReadTimeout, limitDefaultReadTimeout))
}

func (l *Limits) handshakeTimeout() time.Duration {
	return optionalDuration(l.HandshakeTimeout, limitDefaultHandshakeTimeout)
}

func (l *Limits) bodyTooLarge(n int64) bool {
	return l.MaxBodySize > 0 && n > l.MaxBodySize
}

func (s *Server) Limits() Limits { return *s.limits.Load() }

func (s *Server) SetLimits(l Limits) error {
	l = l.withDefaults()
	if err := l.validate(); err != nil {
		return err
	}
	if l.MaxConnsPerIP > 0 && !s.trustedProxies.active && s.perIPConnLimiter.Load() == nil {
		if fresh := newPerIPConnLimiter(); !s.perIPConnLimiter.CompareAndSwap(nil, fresh) {
			fresh.Stop()
		}
	}
	s.limits.Store(&l)
	s.limitsGen.Add(1)
	return nil
}

func (s *Server) perIPInFlightLimit() int64 {
	if !s.trustedProxies.active {
		return 0
	}
	if n := s.limits.Load().MaxConnsPerIP; n > 0 {
		return n
	}
	return 0
}
