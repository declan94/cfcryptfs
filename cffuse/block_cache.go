package cffuse

import (
	"github.com/declan94/cfcryptfs/internal/tlog"
	lru "github.com/hashicorp/golang-lru"
)

// Caches plaintext blocks to speedup sequential read and write(write-on-read)

const (
	maxCacheTotalBytes = 32 * 1024
	maxCacheBlockCount = 4
)

func (ent *nodeEntry) getBlockCache() *lru.Cache {
	if ent.blockCache != nil {
		return ent.blockCache
	}
	cacheCount := maxCacheBlockCount
	if cacheCount*ent.fs.configs.PlainBS > maxCacheTotalBytes {
		cacheCount = maxCacheTotalBytes / ent.fs.configs.PlainBS
	}
	var err error
	ent.blockCache, err = lru.New(cacheCount)
	if err != nil {
		tlog.Warn.Printf("New block cache failed: %v", err)
		return nil
	}
	return ent.blockCache
}

// needCopy: sometimes the cache slice point to memory we only have tempory access.
// 	for example the byte slice data param in the fuse Write call
// 	we need to do copy, otherwise the content data of the slice may change.
func (ent *nodeEntry) cacheBlock(blockNo uint64, content []byte, needCopy bool) {
	cache := ent.getBlockCache()
	if cache != nil {
		var final []byte
		if needCopy {
			final := ent.fs.contentCrypt.PBlockPool.Get()
			copy(final, content)
			final = final[:len(content)]
		} else {
			final = content
		}
		cache.Add(blockNo, final)
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
	tlog.Debug.Printf("Purge block caches")
	cache := ent.getBlockCache()
	if cache != nil {
		cache.Purge()
	}
}
