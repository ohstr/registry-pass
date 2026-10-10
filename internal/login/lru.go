package login

import (
	"container/list"
	"sync"
	"time"
)

type cacheKey [32]byte

type entry struct {
	key cacheKey
	id  Identity
}

// lru caches verified logins by password hash until they expire. A nil
// lru (size 0) caches nothing.
type lru struct {
	mu    sync.Mutex
	size  int
	order *list.List
	items map[cacheKey]*list.Element
	now   func() time.Time
}

func newLRU(size int) *lru {
	if size <= 0 {
		return nil
	}
	return &lru{size: size, order: list.New(), items: map[cacheKey]*list.Element{}, now: time.Now}
}

func (c *lru) get(k cacheKey) (Identity, bool) {
	if c == nil {
		return Identity{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return Identity{}, false
	}
	e := el.Value.(*entry)
	if !e.id.Expires.After(c.now()) {
		c.order.Remove(el)
		delete(c.items, k)
		return Identity{}, false
	}
	c.order.MoveToFront(el)
	return e.id, true
}

func (c *lru) put(k cacheKey, id Identity) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		el.Value.(*entry).id = id
		c.order.MoveToFront(el)
		return
	}
	c.items[k] = c.order.PushFront(&entry{key: k, id: id})
	for c.order.Len() > c.size {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.items, last.Value.(*entry).key)
	}
}

func (c *lru) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
