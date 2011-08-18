/* dnsmasq is Copyright (c) 2000-2011 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

/* Returns RBL_ACTION_{PERMIT|DENY} if the name is in the whitelist or
   blacklist, otherwise returns RBL_ACTION_UNKNOWN. */
int rbl_domain_action(char* name)
{
  unsigned int namelen = strlen(name);

  struct rbl_domain_list *domain;
  for (domain = daemon->rbl_domains ; domain != NULL ; domain = domain->next)
    {
      unsigned int domainlen = strlen(domain->domain_suffix);
      char *matchstart = name + namelen - domainlen;
      if (namelen >= domainlen &&
	  hostname_isequal(matchstart, domain->domain_suffix) &&
	  (domainlen == 0 || namelen == domainlen || *(matchstart-1) == '.' ))
	{
	  return domain->action;
	}
    }
  return RBL_ACTION_UNKNOWN;
}
