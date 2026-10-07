package hub

import (
	"fmt"
	"testing"

	"webtraffik/internal/event"
)

func ev(i int) event.ConnectionEvent { return event.ConnectionEvent{SrcIP: fmt.Sprint(i)} }

func TestRingKeepsNewestInOrder(t *testing.T) {
	h := New()
	for i := 0; i < HistorySize+10; i++ {
		h.Broadcast(ev(i))
	}
	snap := h.Snapshot()
	if len(snap) != HistorySize {
		t.Fatalf("len = %d", len(snap))
	}
	if snap[0].SrcIP != "10" || snap[HistorySize-1].SrcIP != fmt.Sprint(HistorySize+9) {
		t.Errorf("order wrong: first=%s last=%s", snap[0].SrcIP, snap[HistorySize-1].SrcIP)
	}
}

func TestPartialRingAndSeed(t *testing.T) {
	h := New()
	h.Broadcast(ev(1))
	h.Broadcast(ev(2))
	if s := h.Snapshot(); len(s) != 2 || s[0].SrcIP != "1" {
		t.Errorf("partial snapshot = %v", s)
	}
	var seed []event.ConnectionEvent
	for i := 0; i < HistorySize+5; i++ {
		seed = append(seed, ev(i))
	}
	h.Seed(seed)
	s := h.Snapshot()
	if len(s) != HistorySize || s[0].SrcIP != "5" {
		t.Errorf("seeded snapshot len=%d first=%s", len(s), s[0].SrcIP)
	}
	h.Broadcast(ev(9999))
	if s := h.Snapshot(); s[len(s)-1].SrcIP != "9999" || s[0].SrcIP != "6" {
		t.Error("broadcast after seed misordered")
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	h := New()
	slow := h.Subscribe()
	fast := h.Subscribe()
	for i := 0; i < SubscriberBuffer*2; i++ {
		h.Broadcast(ev(i)) // would deadlock if a full channel blocked
		select {
		case <-fast:
		default:
		}
	}
	if len(slow) != SubscriberBuffer {
		t.Errorf("slow buffered %d, want %d", len(slow), SubscriberBuffer)
	}
	h.Unsubscribe(slow)
	h.Unsubscribe(fast)
	if h.Subscribers() != 0 {
		t.Error("subscribers not removed")
	}
}
