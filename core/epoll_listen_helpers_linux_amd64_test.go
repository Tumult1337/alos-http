//go:build linux && amd64

package core

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func epollListen(addr string) (int, error) {
	fd, err := epollBind(addr)
	if err != nil {
		return -1, err
	}
	if err := unix.Listen(fd, epollListenBacklog); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func newEpollWorker(s *Server, addr string, minPrealloc int) (*epollWorker, error) {
	listenerFD, err := epollListen(addr)
	if err != nil {
		return nil, fmt.Errorf("epoll listen %s: %w", addr, err)
	}
	return newEpollWorkerFromFD(s, listenerFD, minPrealloc)
}
