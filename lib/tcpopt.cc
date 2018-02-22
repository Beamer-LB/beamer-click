#include "tcpopt.hh"

CLICK_DECLS

using namespace ClickityClack;

namespace Beamer
{

/* shamelessly adapted from stuff in net/mptcp/mptcp_input.c */
//TODO: refactor
const TCPOption *getFirstOption(int opcode, const click_tcp *tcpHeader)
{
	TCPOptionIterator it(tcpHeader);
	const TCPOption *option;
	
	while ((option = it.next()) != NULL)
	{
		if (option->opcode == opcode)
			return option;
	}
	
	return NULL;
}

}

CLICK_ENDDECLS

ELEMENT_PROVIDES(Beamer_TCPOpt)
ELEMENT_REQUIRES(ClickityClack_TCPOptionIterator)
