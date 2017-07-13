package cffuse

import (
	"github.com/declan94/cfcryptfs/internal/tlog"
	lru "github.com/hashicorp/golang-lru"
)

// Caches plaintext blocks to speedup sequential read and write(write-on-read)

const cacheTotalBytes = 128 * 1024

func (ent *nodeEntry) getBlockCache() *lru.Cache {
	if ent.blockCache != nil {
		return ent.blockCache
	}
	var err error
	ent.blockCache, err = lru.New(cacheTotalBytes / ent.fs.configs.PlainBS)
	if err != nil {
		tlog.Warn.Printf("New block cache failed: %v", err)
		return nil
	}
	return ent.blockCache
}

func (ent *nodeEntry) cacheBlock(blockNo uint64, content []byte) {
	cache := ent.getBlockCache()
	if cache != nil {
		cache.Add(blockNo, content)
	}
}

func (ent *nodeEntry) getCachedBlock(blockNo uint64) []byte {
	cache := ent.getBlockCache()
	if cache == nil {
		return nil
	}
	content, ok := cache.Get(blockNo)
	if ok {
		return content.([]byte)
	}
	return nil
}

func (ent *nodeEntry) removeCachedBlock(blockNo uint64) {
	cache := ent.getBlockCache()
	if cache != nil {
		cache.Remove(blockNo)
	}
}

func (ent *nodeEntry) purgeCachedBlocks() {
	cache := ent.getBlockCache()
	if cache != nil {
		cache.Purge()
	}
}
