#ifndef CLICK_BEAMER_ZKCLIENT_HH
#define CLICK_BEAMER_ZKCLIENT_HH

#include <click/config.h>
#include <click/string.hh>
#include <click/glue.hh>
#include <zookeeper/zookeeper.h>
#include <zlib.h>
#include "dipmap.hh"

CLICK_DECLS

namespace Beamer
{

template <typename DIP_MAP> class ZKClient
{
	struct LogEntry
	{
		uint32_t dip;
		uint32_t bucketCount;
		uint32_t buckets[0];
	} __attribute__((packed));
	
	enum State
	{
		INIT,
		FIND_NEWEST_BLOB,
		UPDATE_FROM_BLOB,
		UPDATE_FROM_GEN,
	};
	
	static const int BUF_SIZE = 100 * 1024 * 1024; /* 100 MB */
	
	const String LATEST_BLOB    = "latest_blob";
	const String LATEST_GEN     = "latest_gen";
	const String GEN_BASE       = "gen";
	const String BLOB_PART_BASE = "blob";

	String root;
	DIP_MAP *dipMap;
	volatile int32_t gen;
	zhandle_t *zooHandle;
	State state;
	
	int32_t latestGen;
	int32_t latestBlob;
	bool live;
	
	char *dataBuf;
	char *nodeBuf;
	
	static void latestGenWatcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
	{
		(void)zh; (void)type; (void)state;
		
		/* some other type of event; ignore */
		if (!path)
			return;
		
		ZKClient<DIP_MAP> *me = (ZKClient *)watcherCtx;
		
		int32_t newLatestGen = me->getInt32(me->root + me->LATEST_GEN, true);
		
		if (newLatestGen > me->latestGen)
			me->latestGen = newLatestGen;
		
		if (me->state == UPDATE_FROM_GEN && me->latestGen > me->gen)
			me->sync();
	}
	
	static void syncComplete(int, const char *, const void *data)
	{
		ZKClient<DIP_MAP> *me = (ZKClient *)data;
		
		me->fsm();
	}
	
	int readNode(String name, bool watch, char *buf, int *size)
	{
		int err;
	
		//click_chatter("zoo_get(%p, %s, %d, %p, %d, %p", zooHandle, name.c_str(), watch, buf, size, NULL);
		err = zoo_get(zooHandle, name.c_str(), watch, buf, size, NULL);
		switch (err)
		{
		case ZOK:
		case ZNONODE:
			break;
			
		case ZNOAUTH:
		case ZBADARGUMENTS:
		case ZINVALIDSTATE:
		case ZMARSHALLINGERROR:
		default:
			click_chatter("zoo_get: %d", err);
			assert(false);
		}
		
		return err;
	}
	
	/* 
	 * shamelessly copied from stackoverflow: 
	 * https://stackoverflow.com/questions/4901842/in-memory-decompression-with-zlib 
	 */
	int inflatez(const void *src, int srcLen, void *dst, int dstLen)
	{
		z_stream strm  = {0};
		strm.total_in  = strm.avail_in  = srcLen;
		strm.total_out = strm.avail_out = dstLen;
		strm.next_in   = (Bytef *) src;
		strm.next_out  = (Bytef *) dst;
		
		strm.zalloc = Z_NULL;
		strm.zfree  = Z_NULL;
		strm.opaque = Z_NULL;
		
		int err = -1;
		
		err = inflateInit2(&strm, (15 + 32)); //15 window bits, and the +32 tells zlib to to detect if using gzip or zlib
		assert(err == Z_OK);
		
		err = inflate(&strm, Z_FINISH);
		assert(err == Z_STREAM_END);
		
		inflateEnd(&strm);
		
		return strm.total_out;
	}
	
	int readCompressedNode(String name, bool watch, char *buf, int *size)
	{
		int nodeSize = BUF_SIZE;
		int err = readNode(name, watch, nodeBuf, &nodeSize);
		if (err != ZOK)
			return err;
		//click_chatter("inflating %s max %d", name.c_str(), *size);
		*size = inflatez(nodeBuf, nodeSize, buf, *size);
		//click_chatter("inflated %d", *size);
		
		return err;
		
	}
	
	int readHugeNode(String name, bool watch, char *buf, int *size)
	{
		int32_t chunks;
		int off = 0;
		int err;

		/* first node */
		{
			int nodeSize = BUF_SIZE;
			err = readNode(name + "_0", watch, nodeBuf, &nodeSize);
			if (err != ZOK)
				return err;
			off += nodeSize;
			
			assert(nodeSize >= sizeof(int32_t));
			chunks = *(reinterpret_cast<int *>(nodeBuf));
			assert(chunks >= 1);
		}
		
		for (int i = 1; i < chunks; i++)
		{
			int nodeSize = BUF_SIZE - off;
			err = readNode(name + "_" + String(i), false, nodeBuf + off, &nodeSize);
			if (err != ZOK)
				return err;
			off += nodeSize;
		}
		*size = inflatez(nodeBuf + sizeof(int32_t), off - sizeof(int32_t), buf, *size);
		
		return err;
	}
	
	int installBlob(int32_t blobNo)
	{
		static const int ENTRY_SIZE = sizeof(typename DIP_MAP::MapEntry);
		int size = BUF_SIZE;
		
		int err = readHugeNode(root + GEN_BASE + "_" + String(blobNo) + "/" + BLOB_PART_BASE, false, dataBuf, &size);
		if (err != ZOK)
			return err;
		assert(size % ENTRY_SIZE == 0);
		assert(size / ENTRY_SIZE == dipMap->size());
		
		dipMap->putEntries(0, reinterpret_cast<typename DIP_MAP::MapEntry *>(dataBuf), dipMap->size());
		gen = blobNo;
		
		//click_chatter("New gen from blob: %d", (int)gen);
		
		return ZOK;
	}
	
	int replayLog(int32_t index)
	{
		int size = BUF_SIZE;
		int err = readHugeNode(root + GEN_BASE + "_" + String(index) + "/log", false, dataBuf, &size);
		char *crt = dataBuf;
		typename DIP_MAP::LogHeader *header;
		
		if (err != ZOK)
			goto done;
		
		header = reinterpret_cast<typename DIP_MAP::LogHeader *>(crt);
		crt += sizeof(*header);
		size -= sizeof(*header);
		
		while (size > 0)
		{
			assert(size >= sizeof(LogEntry));
			
			LogEntry *entry = reinterpret_cast<LogEntry *>(crt);
			int logSize = sizeof(LogEntry) + entry->bucketCount * sizeof(uint32_t);
			
			assert(size >= logSize);
			
			for (int32_t i = 0; i < entry->bucketCount; i++)
				dipMap->updateEntry(entry->buckets[i], entry->dip, *header);
			
			crt += logSize;
			size -= logSize;
		}
		
done:
		return err;
	}
	
	void fsm()
	{
		/* commented syncs replaced with goto again */
again:
		switch (state)
		{
		case INIT:
			//TODO: set thread affinity
	
		case FIND_NEWEST_BLOB:
		{
			int32_t newLatestBlob = getInt32(root + LATEST_BLOB, false);
			
			assert(newLatestBlob > gen && newLatestBlob > latestBlob);
			latestBlob = newLatestBlob;
			
			this->state = UPDATE_FROM_BLOB;
			goto again; //sync();
			break;
		}
			
		case UPDATE_FROM_BLOB:
		{
			int err = installBlob(latestBlob);
			
			if (err == ZOK)
			{
				int32_t newLatestGen = getInt32(root + LATEST_GEN, true);
				
				if (newLatestGen > latestGen)
					latestGen = newLatestGen;
				
				state = UPDATE_FROM_GEN;
				
				if (latestGen > gen)
					goto again; //sync();
			}
			else /* blob got deleted; look for a newer one */
			{
				this->state = FIND_NEWEST_BLOB;
				goto again; //sync();
			}
			break;
		}
			
		case UPDATE_FROM_GEN:
		{
			while (gen < latestGen)
			{
				int err = replayLog(gen + 1);
				
				if (err != ZOK)
				{
					state = FIND_NEWEST_BLOB;
					goto again; //sync();
					break;
				}
				
				gen++;
				
				//click_chatter("New gen from log: %d", (int)gen);
			}
			break;
		}
		}
	}
	
	
public:
	ZKClient(String root, DIP_MAP *ring)
		: root(root), dipMap(ring), gen(-1), zooHandle(NULL), state(INIT), latestGen(-1), latestBlob(-1), live(false)
	{
		zoo_set_debug_level(ZOO_LOG_LEVEL_ERROR);
		dataBuf = new char[BUF_SIZE]; assert(dataBuf);
		nodeBuf = new char[BUF_SIZE]; assert(nodeBuf);
	}
	
	bool isLive() const
	{
		return live;
	}
	
	int32_t getGen() const
	{
		return gen;
	}
	
	DIP_MAP *getDIPMap()
	{
		return dipMap;
	}

	int connect(const String &connectString)
	{
		zooHandle = zookeeper_init(connectString.c_str(), latestGenWatcher, 10000, NULL, this, 0);
		if (!zooHandle)
			return -errno;
		
		live = true;
		return 0;
	}
	
	void sync()
	{
		String rootNode = root.substring(0, root.length() - 1);
		int err = zoo_async(zooHandle, rootNode.c_str(), syncComplete, this);
		assert(err == ZOK);
	}
	
	int32_t getInt32(String name, bool watch)
	{
		int err;
		int size = sizeof(int);
		int ret;
	
		err = readNode(name, watch, reinterpret_cast<char *>(&ret), &size);
		assert(err == ZOK);
		assert(size == sizeof(int));
		assert(ret >= 0);
	
		return ret;
	}

	~ZKClient()
	{
		if (zooHandle)
			zookeeper_close(zooHandle); //error code probably doesn't matter at this point
		
		delete dataBuf;
		delete nodeBuf;
	}
};

}

CLICK_ENDDECLS

#endif /* CLICK_BEAMER_ZKCLIENT_HH */
