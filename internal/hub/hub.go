// Package hub fans live connection events out to WebSocket subscribers and
// keeps a short in-memory history for /api/recent.
package hub

import (
	"sync"

	"webtraffik/internal/event"
)

// HistorySize is the number of recent events retained in memory.
const HistorySize = 1000

// SubscriberBuffer is the per-subscriber channel depth; it absorbs bursts while
// a new client's history replay is in progress.
const SubscriberBuffer = 256

// Hub manages subscribers and a ring buffer of recent events.
type Hub struct {
	mu          sync.Mutex
	subscribers map[chan event.ConnectionEvent]struct{}
	ring        []event.ConnectionEvent // fixed-capacity ring
	next        int                     // next write index
	full        bool
}

// New returns an empty Hub.
func New() *Hub {
	return &Hub{
		subscribers: make(map[chan event.ConnectionEvent]struct{}),
		ring:        make([]event.ConnectionEvent, HistorySize),
	}
}

// Subscribe registers a new subscriber channel.
func (h *Hub) Subscribe() chan event.ConnectionEvent {
	ch := make(chan event.ConnectionEvent, SubscriberBuffer)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber. The channel is not closed; broadcast never
// sends to it after this returns.
func (h *Hub) Unsubscribe(ch chan event.ConnectionEvent) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	h.mu.Unlock()
}

// Subscribers returns the current subscriber count.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}

// Seed replaces the history with events (oldest first), keeping the newest
// HistorySize.
func (h *Hub) Seed(events []event.ConnectionEvent) {
	if len(events) > HistorySize {
		events = events[len(events)-HistorySize:]
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next, h.full = 0, false
	for _, ev := range events {
		h.push(ev)
	}
}

// push appends to the ring; caller holds mu.
func (h *Hub) push(ev event.ConnectionEvent) {
	h.ring[h.next] = ev
	h.next++
	if h.next == HistorySize {
		h.next, h.full = 0, true
	}
}

// Snapshot returns a copy of the history, oldest first.
func (h *Hub) Snapshot() []event.ConnectionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.full {
		return append([]event.ConnectionEvent(nil), h.ring[:h.next]...)
	}
	out := make([]event.ConnectionEvent, 0, HistorySize)
	out = append(out, h.ring[h.next:]...)
	return append(out, h.ring[:h.next]...)
}

// Broadcast records ev in the history and delivers it to every subscriber.
// The subscriber set is snapshotted under the lock and the sends happen after
// releasing it, so subscribe/unsubscribe never wait on fan-out. Slow
// subscribers (full channel) miss the event rather than stalling capture.
func (h *Hub) Broadcast(ev event.ConnectionEvent) {
	h.mu.Lock()
	h.push(ev)
	subs := make([]chan event.ConnectionEvent, 0, len(h.subscribers))
	for ch := range h.subscribers {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}
