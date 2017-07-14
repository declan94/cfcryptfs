package cffuse

import (
	"sync"
	"sync/atomic"

	"github.com/declan94/cfcryptfs/internal/contcrypter"
	lru "github.com/hashicorp/golang-lru"
)

// nodeEntry is an nodeEntry in the nodeEntry table
//  there's always a unique nodeEntry for an opened file.
// 	(even if been opened multiple times and have multiple file handles)
type nodeEntry struct {
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
	header     *contcrypter.FileHeader
	blockCache *lru.Cache
	fs         *CfcryptFS
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
	entries map[QIno]*nodeEntry
}

// Register creates an open file table entry for "qi" (or incrementes the
// reference count if the entry already exists) and returns the entry.
func (enttable *entrytable) register(qi QIno) *nodeEntry {
	enttable.Lock()
	defer enttable.Unlock()

	e := enttable.entries[qi]
	if e == nil {
		e = &nodeEntry{}
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
		// call purgeCacheBlocks to put all cached blocks into PBlockPool
		e.purgeCachedBlocks()
		delete(enttable.entries, qi)
	}
}

// wlock - serializes write accesses to each file (identified by inode number)
// Writing partial blocks means we have to do read-modify-write cycles. We
// really don't want concurrent writes there.
// Concurrent full-block writes could actually be allowed, but are not to
// keep the locking simple.
var enttable entrytable

func init() {
	enttable.entries = make(map[QIno]*nodeEntry)
}

// countingMutex incrementes t.writeLockCount on each Lock() call.
type countingMutex struct {
	sync.RWMutex
}

func (c *countingMutex) Lock() {
	c.RWMutex.Lock()
	atomic.AddUint64(&enttable.writeOpCount, 1)
}

// WriteOpCount returns the write lock counter value. This value is encremented
// each time writeLock.Lock() on a file table entry is called.
func WriteOpCount() uint64 {
	return atomic.LoadUint64(&enttable.writeOpCount)
}
