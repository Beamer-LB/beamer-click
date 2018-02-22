#ifndef CLICK_STATEFULMUX_HH
#define CLICK_STATEFULMUX_HH

#include <click/config.h>
#include <click/element.hh>
#include <click/ipaddress.hh>
#if HAVE_BATCH
#include <click/batchelement.hh>
#endif
#include "lib/dipmap.hh"
#include "lib/zkclient.hh"
#include "lib/ggencapper.hh"
#include "../clickityclack/lib/ipipencapper.hh"
#include "../clickityclack/lib/statetrack.hh"
#include "../clickityclack/lib/fivetuple.hh"

CLICK_DECLS

#if HAVE_BATCH
class StatefulMux: public BatchElement
#else
class StatefulMux: public Element
#endif
{
public:
	StatefulMux();
	
	~StatefulMux();
	
	const char *class_name() const { return "StatefulMux"; }
	
	const char *port_count() const { return "1/1"; }
	
	const char *processing() const { return AGNOSTIC; }
	
	int configure(Vector<String> &conf, ErrorHandler *errh);
	
	int initialize(ErrorHandler *errh);
	
	Packet *simple_action(Packet *p);
	
#if HAVE_BATCH
	PacketBatch *simple_action_batch(PacketBatch *head);
#endif
	
	static int writeHandler(const String &conf, Element *e, void *thunk, ErrorHandler *errh);
	
	static String readHandler(Element *e, void *thunk);
	
	void add_handlers();
	
private:
	ClickityClack::IPIPEncapper ipipEncapper;
	Beamer::GGEncapper ggEncapper;
	
	IPAddress vip;
	
	Beamer::DIPHistoryMap bucketMap;
	Beamer::ZKClient<Beamer::DIPHistoryMap> hashZkClient;
	
	Beamer::PlainDIPMap idMap;
	Beamer::ZKClient<Beamer::PlainDIPMap> idZkClient;
	
	struct MuxState: public ClickityClack::State<ClickityClack::FiveTuple>
	{
		uint32_t dip;
		
		MuxState();
		
		MuxState(ClickityClack::FiveTuple tuple, uint32_t dip)
			: ClickityClack::State<ClickityClack::FiveTuple>(tuple), dip(dip) {}
	};
	
	ClickityClack::StateTrack<MuxState> **states;
	
	Packet *handleTCP(Packet *p, unsigned int cpuID, click_jiffies_t now);
	Packet *handleUDP(Packet *p);
};

CLICK_ENDDECLS

#endif /* CLICK_STATEFULMUX_HH */
