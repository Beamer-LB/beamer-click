#ifndef CLICK_BEAMERMUX_HH
#define CLICK_BEAMERMUX_HH

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

CLICK_DECLS

#if HAVE_BATCH
class BeamerMux: public BatchElement
#else
class BeamerMux: public Element
#endif
{
public:
	BeamerMux();
	
	~BeamerMux();
	
	const char *class_name() const { return "BeamerMux"; }
	
	const char *port_count() const { return "1-/="; }
	
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
	
	Packet *handleTCP(Packet *p);
	Packet *handleUDP(Packet *p);
};

CLICK_ENDDECLS

#endif /* CLICK_BEAMERMUX_HH */
