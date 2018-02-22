#include "statefulmux.hh"
#include <click/args.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/error.hh>
#include "../clickityclack/external/freebsdbob.hh"
#include "../clickityclack/lib/checksumfixup.hh"
#include "lib/tcpopt.hh"
#include "lib/p4crc32.hh"

CLICK_DECLS

using namespace Beamer;
using namespace ClickityClack;

#define CLICK_BEAMER_HASHFN_BOB 0
#define CLICK_BEAMER_HASHFN_CRC 1

#ifndef CLICK_BEAMER_HASHFN
#define CLICK_BEAMER_HASHFN CLICK_BEAMER_HASHFN_CRC
#endif

#define CLICK_BEAMER_STATEFUL_DAISY 0

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

StatefulMux::StatefulMux()
	: hashZkClient("/beamer/mux_ring/", &bucketMap), idZkClient("/beamer/id/", &idMap) {}

StatefulMux::~StatefulMux() {}

static const int RESERVED_PORT_COUNT = 1024;

int StatefulMux::configure(Vector<String> &conf, ErrorHandler *errh)
{
	String zkConnectString;
	int ringSize = 1;
	int maxStates = -1;
	
	if (Args(conf, this, errh)
		.read("ZK",         StringArg(),                     zkConnectString)
		.read("RING_SIZE",  BoundedIntArg(0, (int)0x800000), ringSize)
		.read("MAX_STATES", IntArg(),                        maxStates)
		.complete() < 0)
	{
		return -1;
	}
	
	if (maxStates <= 0)
		return errh->error("Bad MAX_STATES");

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
	
	states = new StateTrack<MuxState>*[click_max_cpu_ids()]; assert(states);
	for (int i = 0; i < click_max_cpu_ids(); i++)
	{
		states[i] = new StateTrack<MuxState>(4 * 60 * CLICK_HZ, maxStates / click_max_cpu_ids()); assert(states[i]);
	}
	
	return 0;
}

int StatefulMux::initialize(ErrorHandler *errh)
{
	(void)errh;
	
	if (hashZkClient.isLive())
		hashZkClient.sync();
	
	if (idZkClient.isLive())
		idZkClient.sync();
	
	return 0;
}

Packet *StatefulMux::handleTCP(Packet *p, unsigned int cpuID, click_jiffies_t now)
{
	const click_ip *ipHeader = p->ip_header();
	const click_tcp *tcpHeader = p->tcp_header();
	uint32_t dip;
#if CLICK_BEAMER_STATEFUL_DAISY
	uint32_t prevDip = 0;
	uint32_t ts;
	uint32_t gen = htonl(hashZkClient.getGen());
#endif
	
	if (ntohs(tcpHeader->th_dport) < RESERVED_PORT_COUNT)
	{
		uint32_t hash = beamerHash(ipHeader, tcpHeader);
		DIPHistoryEntry entry = bucketMap.get(hash);
		MuxState *state = states[cpuID]->getBestEffort(FiveTuple(ipHeader, tcpHeader), now);
		
		if (state)
		{
			states[cpuID]->refresh(state, now);
			dip = state->dip;
#if CLICK_BEAMER_STATEFUL_DAISY
			if (dip == entry.current)
			{
				prevDip = entry.prev;
				ts = entry.timestamp;
			}
#endif
		}
		else
		{
			dip = entry.current;
#if CLICK_BEAMER_STATEFUL_DAISY
			prevDip = entry.prev;
			ts = entry.timestamp;
#endif
			
			state = states[cpuID]->allocate();
			state = new(state) MuxState(FiveTuple(ipHeader, tcpHeader), dip);
			states[cpuID]->putBestEffort(state, now);
		}
	}
	else
	{
		uint16_t id = ntohs(tcpHeader->th_dport);
		dip = idMap.get(id);
	}

#if CLICK_BEAMER_STATEFUL_DAISY	
	if (!prevDip || prevDip == dip)
#endif
		return ipipEncapper.encapsulate(p, vip.addr(), dip);

#if CLICK_BEAMER_STATEFUL_DAISY	
	return ggEncapper.encapsulate(p, vip.addr(), dip, prevDip, ts, gen);
#endif
}

Packet *StatefulMux::handleUDP(Packet *p)
{
	uint32_t hash = beamerHash(p->ip_header(), p->udp_header());
	uint32_t dip = bucketMap.get(hash).current;
	
	return ipipEncapper.encapsulate(p, vip.addr(), dip);
}

#if HAVE_BATCH
PacketBatch *StatefulMux::simple_action_batch(PacketBatch *head)
{
	Packet *current = head;
	Packet *last = head;
	unsigned int cpuID = click_current_cpu_id();
	click_jiffies_t now = click_jiffies();
	
	while (current != NULL)
	{
		/* do stuff */
		uint8_t proto = current->ip_header()->ip_p;
		Packet *result = NULL;
		
		switch (proto)
		{
		case IPPROTO_TCP:
			result = handleTCP(current, cpuID, now);
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

Packet *StatefulMux::simple_action(Packet *p)
{
	uint8_t proto = p->ip_header()->ip_p;
	unsigned int cpuID = click_current_cpu_id();
	click_jiffies_t now = click_jiffies();
	
	switch (proto)
	{
	case IPPROTO_TCP:
		return handleTCP(p, cpuID, now);
		
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

int StatefulMux::writeHandler(const String &conf, Element *e, void *thunk, ErrorHandler *errh)
{
	StatefulMux *me = (StatefulMux *)e;
	
	Vector<unsigned long> buckets;
	IPAddress dip;
	Vector<String> tokens;
	
	DIPHistoryLogHeader ts;
	
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
		
	default:
		return errh->error("bad operation");
	}
	
	return 0;
}

String StatefulMux::readHandler(Element *e, void *thunk)
{
	StatefulMux *me = (StatefulMux *)e;
	
	switch ((intptr_t)thunk)
	{
	case H_GEN:
		return String() + me->hashZkClient.getGen();
		
	default:
		return "<error: bad operation>";
	}
	
	return "";
}

void StatefulMux::add_handlers()
{
	add_write_handler("assign", &writeHandler, H_ASSIGN);
	
	add_read_handler("gen", &readHandler, H_GEN);
}

CLICK_ENDDECLS

EXPORT_ELEMENT(StatefulMux)

ELEMENT_REQUIRES(Beamer_ZKClient)
ELEMENT_REQUIRES(Beamer_TCPOpt)
ELEMENT_REQUIRES(ClickityClack_IPIPEncapper)
ELEMENT_REQUIRES(Beamer_GGEncapper)
