package cffuse

import (
	"sync"
	"sync/atomic"

	"github.com/Declan94/cfcryptfs/internal/contcrypter"
)

// fentry is an entry in the entry table
type entry struct {
	// Reference count
	refCount int
	// ContentLock guards the file content from concurrent writes. Every writer
	// must take this lock before modifying the file content.
	contentLock countingMutex
	// HeaderLock guards the file header (in this struct) and the file header (on
	// disk). Take HeaderLock.RLock() to make sure the file header does not change
	// behind your back. If you modify the file header, you must take
	// HeaderLock.Lock().
	headerLock sync.RWMutex
	// the file obejct
	header *contcrypter.FileHeader
}

func (en *entry) newHeader(mode uint32) {
	en.headerLock.Lock()
	defer en.headerLock.Unlock()
	en.header = contcrypter.NewFileHeader(mode)
}

type entrytable struct {
	// writeOpCount counts entry.ContentLock.Lock() calls. As every operation that
	// modifies a file should
	// call it, this effectively serves as a write-operation counter.
	// The variable is accessed without holding any locks so atomic operations
	// must be used. It must be the first element of the struct to guarantee
	// 64-bit alignment.
	writeOpCount uint64
	// Protects map access
	sync.Mutex
	// Table entries
	entries map[QIno]*entry
}

// Register creates an open file table entry for "qi" (or incrementes the
// reference count if the entry already exists) and returns the entry.
func (enttable *entrytable) register(qi QIno) *entry {
	enttable.Lock()
	defer enttable.Unlock()

	e := enttable.entries[qi]
	if e == nil {
		e = &entry{}
		enttable.entries[qi] = e
	}
	e.refCount++
	return e
}

// Unregister decrements the reference count for "qi" and deletes the entry from
// the open file table if the reference count reaches 0.
func (enttable *entrytable) unregister(qi QIno) {
	enttable.Lock()
	defer enttable.Unlock()

	e := enttable.entries[qi]
	e.refCount--
	if e.refCount == 0 {
		delete(enttable.entries, qi)
	}
}

// wlock - serializes write accesses to each file (identified by inode number)
// Writing partial blocks means we have to do read-modify-write cycles. We
// really don't want concurrent writes there.
// Concurrent full-block writes could actually be allowed, but are not to
// keep the locking simple.
var enttable entrytable

// countingMutex incrementes t.writeLockCount on each Lock() call.
type countingMutex struct {
	sync.Mutex
}

func (c *countingMutex) Lock() {
	c.Lock()
	atomic.AddUint64(&enttable.writeOpCount, 1)
}

// WriteOpCount returns the write lock counter value. This value is encremented
// each time writeLock.Lock() on a file table entry is called.
func WriteOpCount() uint64 {
	return atomic.LoadUint64(&enttable.writeOpCount)
}
