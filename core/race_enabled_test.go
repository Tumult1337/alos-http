//go:build linux && amd64 && race

package core

// raceEnabled reports whether the race detector is compiled in. It instruments
// every allocation, so allocation budgets are meaningless under it.
const raceEnabled = true
