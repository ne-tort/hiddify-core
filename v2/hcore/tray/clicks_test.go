package tray

import (
	"testing"
	"time"
)

func TestIsDoubleClick(t *testing.T) {
	base := time.Now()
	if isDoubleClick(base, time.Time{}) {
		t.Fatal("first click should not be double")
	}
	if !isDoubleClick(base.Add(200*time.Millisecond), base) {
		t.Fatal("200ms gap should count as double click")
	}
	if isDoubleClick(base.Add(500*time.Millisecond), base) {
		t.Fatal("500ms gap should not count as double click")
	}
}
