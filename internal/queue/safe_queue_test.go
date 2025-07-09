package queue_test

import (
	"testing"

	. "github.com/sem-hub/snake-net/internal/queue"
)

func TestQueue(t *testing.T) {
	q := NewQueue()
	for j := 0; j < 100; j++ {
		q.Push(j)
	}
	if q.Len() != 100 {
		t.Error(
			"Expected Queue length 100",
			"actual", q.Len(),
		)
	}
	n := q.Pop()
	if n != 0 {
		t.Error(
			"Expected Queue pop 0",
			"actual", n,
		)
	}
	q.Push(1000)
	n = q.Pop()
	if n != 1 {
		t.Error(
			"Expected Queue pop 1",
			"actual", n,
		)
	}

	for j := 1; j < 100; j++ {
		q.Pop()
	}
	if q.Len() != 0 {
		t.Error(
			"Expected Queue length 0",
			"actual", q.Len(),
		)
	}
}
