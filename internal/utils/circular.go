package utils

import (
	"sync"
)

type CircularBuffer struct {
	buffer       []interface{}
	size         int
	readPointer  int
	writePointer int
	count        int
	lock         sync.Mutex
}

func NewCircularBuffer(size int) *CircularBuffer {
	return &CircularBuffer{
		buffer:       make([]interface{}, size),
		size:         size,
		readPointer:  0,
		writePointer: 0,
		count:        0,
		lock:         sync.Mutex{},
	}
}
func (c *CircularBuffer) Push(data interface{}) {
	c.lock.Lock()
	if c.count == c.size {
		c.readPointer = (c.readPointer + 1) % c.size
	} else {
		c.count++
	}
	c.buffer[c.writePointer] = data
	c.writePointer = (c.writePointer + 1) % c.size
	c.lock.Unlock()
}

func (c *CircularBuffer) Find(comp func(index interface{}) bool) (interface{}, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.count == 0 {
		return nil, false
	}

	for i := 0; i < c.count; i++ {
		index := (c.readPointer + i) % c.size
		if comp(c.buffer[index]) {
			return c.buffer[index], true
		}
	}
	return nil, false
}
