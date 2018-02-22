#ifndef CLICK_BEAMER_GGENCAPPER_HH
#define CLICK_BEAMER_GGENCAPPER_HH

#include <click/config.h>
#include <clicknet/ip.h>
#include <click/packet.hh>
#include <click/glue.hh>
#include "../../clickityclack/lib/ipoption.hh"

CLICK_DECLS

namespace Beamer
{

struct PrevDIPOption: public ClickityClack::IPOption
{
	uint16_t padding;
	uint32_t pdip;
	uint32_t ts;
	uint32_t gen;
} __attribute__((packed));

struct IPHeaderWithPrevDIP
{
	click_ip iph;
	PrevDIPOption opt;
} __attribute__((packed));

class GGEncapper
{
	IPHeaderWithPrevDIP iphPDip;
	
public:
	GGEncapper();
	
	WritablePacket *encapsulate(Packet *p, uint32_t vip, uint32_t dip, uint32_t pdip, uint32_t ts, uint32_t gen);
};

}

CLICK_ENDDECLS

#endif /* CLICK_BEAMER_TSENCAPPER_HH */
