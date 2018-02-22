#ifndef CLICK_BEAMER_TCPOPT_HH
#define CLICK_BEAMER_TCPOPT_HH

#include <click/config.h>
#include <click/glue.hh>
#include "../../clickityclack/lib/tcpoptioniterator.hh"
#include "../../clickityclack/lib/staticbyteswap.hh"

CLICK_DECLS

namespace Beamer
{

const int TCPOPT_MPTCP = 30;
const int MPTCP_SUB_CAPABLE = 0;
const int MPTCP_SUB_JOIN = 1;

struct TCPTimestamp: public ClickityClack::TCPOption
{
	uint32_t tsval;
	uint32_t tsecr;
} __attribute__((packed));

struct MPTCPOption: public ClickityClack::TCPOption
{
#if CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	uint8_t ver:4,
		sub:4;
#elif CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	uint8_t sub:4,
		ver:4;
#else
#error	"No byte order defined"
#endif
} __attribute__((packed));

struct MPTCPCapableSyn: public MPTCPOption
{
#if CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	uint8_t h:1,
		rsv:5,
		b:1,
		a:1;
#elif CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	uint8_t a:1,
		b:1,
		rsv:5,
		h:1;
#else
#error	"No byte order defined"
#endif
	uint64_t sender_key;
} __attribute__((packed));

struct MPTCPJoinSyn: public MPTCPOption
{
	uint8_t addr_id;
	uint32_t token;
	uint32_t nonce;
} __attribute__((__packed__));


const ClickityClack::TCPOption *getFirstOption(int opcode, const click_tcp *tcpHeader);

inline const TCPTimestamp *getTimestampFast(const click_tcp *tcpHeader)
{
	const uint32_t *ptr = reinterpret_cast<const uint32_t *>(tcpHeader + 1);
	
	if (*ptr == ClickityClack::StaticHTONL<(TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP>::value)
		return reinterpret_cast<const TCPTimestamp *>(reinterpret_cast<const uint8_t *>(tcpHeader + 1) + 2);
	return NULL;
}

inline const TCPTimestamp *getTimestamp(const click_tcp *tcpHeader)
{
	const TCPTimestamp *ret = getTimestampFast(tcpHeader);
	
	if (!ret)
	{
		ret = (TCPTimestamp *)getFirstOption(TCPOPT_TIMESTAMP, tcpHeader);
		
		if (!ret || ret->opsize != TCPOLEN_TIMESTAMP)
			return NULL;
	}
	
	return ret;
}

//TODO: implement and use if MP_JOIN can coexist with other MPTCP options
//const MPTCPOption *getFirstMPTCPOption(int sub, const click_tcp *tcpHeader);

inline const MPTCPJoinSyn *getMPTCPJoinSyn(const click_tcp *tcpHeader)
{
	const MPTCPJoinSyn *opt = (const MPTCPJoinSyn *)getFirstOption(TCPOPT_MPTCP, tcpHeader);
	
	if (!opt || opt->opsize != sizeof(MPTCPJoinSyn) || opt->sub != MPTCP_SUB_JOIN)
		return NULL;
	
	return opt;
}

}

CLICK_ENDDECLS

#endif /* CLICK_BEAMER_TCPOPT_HH */
