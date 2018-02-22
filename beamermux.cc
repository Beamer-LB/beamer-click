#include "beamermux.hh"
#include <click/args.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/error.hh>
#include "../clickityclack/external/freebsdbob.hh"
#include "../clickityclack/lib/checksumfixup.hh"
#include "lib/tcpopt.hh"
#include "lib/p4crc32.hh"
#include "lib/dumper.hh"

CLICK_DECLS

using namespace Beamer;
using namespace ClickityClack;

#define CLICK_BEAMER_HASHFN_BOB 0
#define CLICK_BEAMER_HASHFN_CRC 1

#ifndef CLICK_BEAMER_HASHFN
#define CLICK_BEAMER_HASHFN CLICK_BEAMER_HASHFN_CRC
#endif

static inline uint32_t beamerHash(const click_ip *ipHeader, const click_tcp *tcpHeader)
{
#if CLICK_BEAMER_HASHFN == CLICK_BEAMER_HASHFN_BOB
	return freeBSDBob(ipHeader->ip_src.s_addr, tcpHeader->th_sport, tcpHeader->th_dport);
#elif CLICK_BEAMER_HASHFN == CLICK_BEAMER_HASHFN_CRC
	struct HashTouple touple = { ipHeader->ip_src.s_addr, tcpHeader->th_sport };
	return p4_crc32_6((char *)&touple);
#else
#error Invalid CLICK_BEAMER_HASHFN
#endif
}

static inline uint32_t beamerHash(const click_ip *ipHeader, const click_udp *udpHeader)
{
#if CLICK_BEAMER_HASHFN == CLICK_BEAMER_HASHFN_BOB
	return freeBSDBob(ipHeader->ip_src.s_addr, udpHeader->uh_sport, udpHeader->uh_dport);
#elif CLICK_BEAMER_HASHFN == CLICK_BEAMER_HASHFN_CRC
	struct HashTouple touple = { ipHeader->ip_src.s_addr, udpHeader->uh_sport };
	return p4_crc32_6((char *)&touple);
#else
#error Invalid CLICK_BEAMER_HASHFN
#endif
}

BeamerMux::BeamerMux()
	: hashZkClient("/beamer/mux_ring/", &bucketMap), idZkClient("/beamer/id/", &idMap) {}

BeamerMux::~BeamerMux() {}

static const int RESERVED_PORT_COUNT = 1024;

int BeamerMux::configure(Vector<String> &conf, ErrorHandler *errh)
{
	String zkConnectString;
	int ringSize = 1;
	
	if (Args(conf, this, errh)
		.read("ZK",        StringArg(),                     zkConnectString)
		.read("RING_SIZE", BoundedIntArg(0, (int)0x800000), ringSize)
		.complete() < 0)
	{
		return -1;
	}

	if (zkConnectString.length() != 0)
	{
		if (hashZkClient.connect(zkConnectString) < 0)
			return errh->error("Error connectiong to ZooKeeper: %s", strerror(errno));
		if (idZkClient.connect(zkConnectString) < 0)
			return errh->error("Error connectiong to ZooKeeper: %s", strerror(errno));
		vip = hashZkClient.getInt32("/beamer/config/vip", false);
		bucketMap.init(hashZkClient.getInt32("/beamer/config/ring_size", false));
	}
	else
	{
		vip = 0;
		bucketMap.init(ringSize);
	}
	
	idMap.init(0x10000);
	
	return 0;
}

int BeamerMux::initialize(ErrorHandler *errh)
{
	(void)errh;
	
	if (hashZkClient.isLive())
		hashZkClient.sync();
	
	if (idZkClient.isLive())
		idZkClient.sync();
	
	return 0;
}

Packet *BeamerMux::handleTCP(Packet *p)
{
	const click_ip *ipHeader = p->ip_header();
	const click_tcp *tcpHeader = p->tcp_header();
	uint32_t dip;
	uint32_t prevDip = 0;
	uint32_t ts;
	uint32_t gen = htonl(hashZkClient.getGen());
	
	if (ntohs(tcpHeader->th_dport) < RESERVED_PORT_COUNT)
	{
		uint32_t hash = beamerHash(ipHeader, tcpHeader);
		DIPHistoryEntry entry = bucketMap.get(hash);
		dip = entry.current;
		prevDip = entry.prev;
		ts = entry.timestamp;
		
		return ggEncapper.encapsulate(p, vip.addr(), dip, prevDip, ts, gen);
	}
	else
	{
		uint16_t id = ntohs(tcpHeader->th_dport);
		dip = idMap.get(id);
		
		return ipipEncapper.encapsulate(p, vip.addr(), dip);
	}
}

Packet *BeamerMux::handleUDP(Packet *p)
{
	uint32_t hash = beamerHash(p->ip_header(), p->udp_header());
	uint32_t dip = bucketMap.get(hash).current;
	
	return ipipEncapper.encapsulate(p, vip.addr(), dip);
}

#if HAVE_BATCH
PacketBatch *BeamerMux::simple_action_batch(PacketBatch *head)
{
	Packet *current = head;
	Packet *last = head;
	
	while (current != NULL)
	{
		/* do stuff */
		uint8_t proto = current->ip_header()->ip_p;
		Packet *result = NULL;
		
		switch (proto)
		{
		case IPPROTO_TCP:
			result = handleTCP(current);
			break;
			
		case IPPROTO_UDP:
			result = handleUDP(current);
			break;
			
		default:
			result = current;
			break;
		}
		
		if (current == head)
		{
			head = PacketBatch::start_head(result);
			head->set_next(current->next());
		}
		else
		{
			last->set_next(result);
			result->set_next(current->next());
		}
		
		last = result;
		current = result->next();
	}
	return head;
}
#endif

Packet *BeamerMux::simple_action(Packet *p)
{
	uint8_t proto = p->ip_header()->ip_p;
	
	switch (proto)
	{
	case IPPROTO_TCP:
		return handleTCP(p);
		
	case IPPROTO_UDP:
		return handleUDP(p);
		
	default:
		return p;
	}
	
	p->kill();
	return NULL;
}

enum
{
	/* write */
	H_ASSIGN,
	H_DUMP,
	
	/* read */
	H_GEN,
};

static void tokenize(const String &str, int startIndex, Vector<String> *vec)
{
	if (startIndex == str.length())
		return;
	
	int spaceIndex = str.find_left(' ', startIndex);
	
	if (spaceIndex == -1) /* no spaces */
	{
		vec->push_back(str.substring(startIndex, str.length() - startIndex));
	}
	else if (spaceIndex == startIndex) /* starts with space */
	{
		tokenize(str, startIndex + 1, vec);
	}
	else /* got some space */
	{
		vec->push_back(str.substring(startIndex, spaceIndex - startIndex));
		tokenize(str, spaceIndex + 1, vec);
	}
}

int BeamerMux::writeHandler(const String &conf, Element *e, void *thunk, ErrorHandler *errh)
{
	BeamerMux *me = (BeamerMux *)e;
	
	Vector<unsigned long> buckets;
	IPAddress dip;
	Vector<String> tokens;
	
	DIPHistoryLogHeader ts;
	
	int err;
	
	switch ((intptr_t)thunk)
	{
	case H_ASSIGN:
		tokenize(conf, 0, &tokens);
		if (tokens.size() < 2)
			return errh->error("expected 2+ arguments, got %d", tokens.size());
		
		if (!IPAddressArg().parse(tokens[0], dip))
			return errh->error("bad DIP");
		
		for (int i = 1; i < tokens.size(); i++)
		{
			int index;
			
			if (!IntArg().parse(tokens[i], index))
				return errh->error("bad index %s", tokens[i].c_str());
			buckets.push_back(index);
		}
		
		ts.timestamp = time(NULL);
		for (int i = 0; i < buckets.size(); i++)
			me->bucketMap.updateEntry(buckets[i], dip.addr(), ts);
		
		break;
		
	case H_DUMP:
		err = Dumper::dump<Beamer::ZKClient<Beamer::DIPHistoryMap> >(&me->hashZkClient, "hash_dump.raw");
		if (err < 0)
			return errh->error("error dumping: %d (%s)", -err, strerror(-err));
		err = Dumper::dump<Beamer::ZKClient<Beamer::PlainDIPMap> >(&me->idZkClient, "id_dump.raw");
		if (err < 0)
			return errh->error("error dumping: %d (%s)", -err, strerror(-err));
		break;
		
	default:
		return errh->error("bad operation");
	}
	
	return 0;
}

String BeamerMux::readHandler(Element *e, void *thunk)
{
	BeamerMux *me = (BeamerMux *)e;
	
	switch ((intptr_t)thunk)
	{
	case H_GEN:
		return String() + me->hashZkClient.getGen();
		
	default:
		return "<error: bad operation>";
	}
	
	return "";
}

void BeamerMux::add_handlers()
{
	add_write_handler("assign", &writeHandler, H_ASSIGN);
	add_write_handler("dump",   &writeHandler, H_DUMP);
	
	add_read_handler("gen", &readHandler, H_GEN);
}

CLICK_ENDDECLS

EXPORT_ELEMENT(BeamerMux)

ELEMENT_REQUIRES(Beamer_ZKClient)
ELEMENT_REQUIRES(Beamer_TCPOpt)
ELEMENT_REQUIRES(ClickityClack_IPIPEncapper)
ELEMENT_REQUIRES(Beamer_GGEncapper)
ELEMENT_REQUIRES(Beamer_P4CRC32)
