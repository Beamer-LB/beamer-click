#include "ggencapper.hh"
#include <click/glue.hh>
#include "../../clickityclack/lib/checksumfixup.hh"
#include "../../clickityclack/lib/pktmemcpy.hh"

CLICK_DECLS

using namespace ClickityClack;

namespace Beamer
{

GGEncapper::GGEncapper()
{
	memset(&iphPDip, 0, sizeof(iphPDip));
	iphPDip.iph.ip_v = 4;
	iphPDip.iph.ip_hl = sizeof(iphPDip) >> 2;
	iphPDip.iph.ip_ttl = 250;
	iphPDip.iph.ip_p = IPPROTO_IPIP;
	iphPDip.opt.copied = 0;
	iphPDip.opt.oclass = 3; /* reserved... for us B) */
	iphPDip.opt.num = 1; /* could be anything */
	iphPDip.opt.len = sizeof(iphPDip.opt);
#if HAVE_FAST_CHECKSUM
	iphKey.iph.ip_sum = ip_fast_csum((unsigned char *)&iphPDip, sizeof(iphPDip));
#else
	iphPDip.iph.ip_sum = click_in_cksum((unsigned char *)&iphPDip, sizeof(iphPDip));
#endif
}

WritablePacket *GGEncapper::encapsulate(Packet *p, uint32_t vip, uint32_t dip, uint32_t pdip, uint32_t ts, uint32_t gen)
{
	size_t displaceLen = p->end_data() - p->network_header();
	size_t displaceDWords = displaceLen / 8 + (displaceLen % 8 ? 1 : 0);
	WritablePacket *wp = p->put(sizeof(IPHeaderWithPrevDIP));
	size_t oldIPLen = ntohs(wp->ip_header()->ip_len);
	
	if (!wp)
		return 0;
	
	/* make room */
	moveMemBulk(reinterpret_cast<uint64_t *>(wp->network_header()), reinterpret_cast<uint64_t *>(wp->network_header() + sizeof(IPHeaderWithPrevDIP)), displaceDWords);
	
	IPHeaderWithPrevDIP *ip = reinterpret_cast<IPHeaderWithPrevDIP *>(wp->ip_header());
	
	memcpyFast(reinterpret_cast<unsigned char *>(ip), reinterpret_cast<unsigned char *>(&iphPDip), sizeof(IPHeaderWithPrevDIP));
	
	ip->iph.ip_src.s_addr = vip;
	ip->iph.ip_dst.s_addr = dip;
	ip->iph.ip_len = htons(oldIPLen + sizeof(IPHeaderWithPrevDIP));
	ip->opt.pdip = pdip;
	ip->opt.ts = ts;
	ip->opt.gen = gen;
	
	ip->iph.ip_sum = checksumFold(
		checksumFixup32(0, vip,
		checksumFixup32(0, dip,
		checksumFixup16(0, ip->iph.ip_len,
		checksumFixup32(0, pdip,
		checksumFixup32(0, ts,
		checksumFixup32(0, gen,
		ip->iph.ip_sum)))))));
	
	wp->set_ip_header(&ip->iph, sizeof(IPHeaderWithPrevDIP));
	
	return wp;
}

}

CLICK_ENDDECLS

ELEMENT_PROVIDES(Beamer_GGEncapper)
