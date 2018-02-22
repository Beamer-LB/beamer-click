#ifndef CLICK_BEAMER_DUMPER_HH
#define CLICK_BEAMER_DUMPER_HH

#include <click/config.h>
#include <click/glue.hh>
#include <click/string.hh>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "zkclient.hh"

CLICK_DECLS

namespace Beamer
{

template <typename DIP_MAP> class ZKClient;

#define CLICK_BEAMER_DUMPER_CHECK(stuff) \
	{ \
		int err = (stuff); \
		if (err < 0) \
			return err; \
	}
		
namespace Dumper
{
	int writeAll(int fd,  const void *buf, size_t count)
	{
		size_t written = 0;
		
		while (written < count)
		{
			ssize_t bytes = write(fd, (char *)buf + written, count - written);
			if (bytes == 0)
				return -EIO;
			if (bytes > 0)
			{
				written += bytes;
				continue;
			}
			if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
				continue;
			
			return -errno;
		}
		return count;
	}
	
	template <typename T> int writeObj(int fd,  const T stuff)
	{
		return writeAll(fd, &stuff, sizeof(T));
	}

	template <typename T> int dump(T *dumpee, int fd);
	
	template <> int dump<DIPHistoryMap>(DIPHistoryMap *dumpee, int fd)
	{
		unsigned long size = dumpee->size();
		CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, (uint32_t)size));
		for (unsigned long i = 0; i < size; i++)
		{
			DIPHistoryEntry entry = dumpee->get(i);
			CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, entry.current));
			CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, entry.prev));
			CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, entry.timestamp));
		}
	}
	
	template <> int dump<PlainDIPMap>(PlainDIPMap *dumpee, int fd)
	{
		unsigned long size = dumpee->size();
		CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, (uint32_t)size));
		for (unsigned long i = 0; i < size; i++)
		{
			uint32_t ip = dumpee->get(i);
			CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, ip));
		}
	}
	
//	template <>
//	template <typename T>
//	int dump<ZKClient<T> >(ZKClient<T> *dumpee, int fd)
//	{
//		CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, dumpee->getGen()));
//		CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, dumpee->getDIPMap()));
//	}
	
	template <> int dump<ZKClient<DIPHistoryMap> >(ZKClient<DIPHistoryMap> *dumpee, int fd)
	{
		CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, (uint32_t)dumpee->getGen()));
		CLICK_BEAMER_DUMPER_CHECK(dump(dumpee->getDIPMap(), fd));
	}
	
	template <> int dump<ZKClient<PlainDIPMap> >(ZKClient<PlainDIPMap> *dumpee, int fd)
	{
		CLICK_BEAMER_DUMPER_CHECK(writeObj(fd, (uint32_t)dumpee->getGen()));
		CLICK_BEAMER_DUMPER_CHECK(dump(dumpee->getDIPMap(), fd));
	}
	
	template <typename T> int dump(T *dumpee, String filename)
	{
		int fd = open(filename.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0600);
		if (fd < 0)
			return -errno;
		int ret = dump(dumpee, fd);
		close(fd);
		return ret;
		
	}
}

}

CLICK_ENDDECLS

#endif /* CLICK_BEAMER_DUMPER_HH */
