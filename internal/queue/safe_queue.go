package queue

import (
	"container/list"
	"sync"
)

type Queue struct {
	lst  *list.List
	lock sync.Mutex
}

func NewQueue() *Queue {
	q := &Queue{}
	q.lst = list.New()
	return q
}

func (q *Queue) Push(v any) {
	q.lock.Lock()
	defer q.lock.Unlock()
	q.lst.PushBack(v)
}

func (q *Queue) Pop() any {
	q.lock.Lock()
	defer q.lock.Unlock()
	if q.lst.Len() == 0 {
		return nil
	} else {
		return q.lst.Remove(q.lst.Front())
	}
}

func (q *Queue) Len() int {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.lst.Len()
}

func (q *Queue) IsEmpty() bool {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.lst.Len() == 0
}
