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

#include <string.h>

/* Checks for name in list and returns 1 if it is present. */
static int check_list(const struct rbl_domain_list *list, char *name)
{
  unsigned int namelen = strlen(name);

  const struct rbl_domain_list *domain;
  for (domain = list ; domain != NULL ; domain = domain->next)
    {
      unsigned int domainlen = strlen(domain->domain_suffix);
      char *matchstart = name + namelen - domainlen;
      if (namelen >= domainlen &&
	  hostname_isequal(matchstart, domain->domain_suffix) &&
	  (domainlen == 0 || namelen == domainlen || *(matchstart-1) == '.' ))
	{
	  return 1;
	}
    }
  return 0;
}

/* Returns 1 if name is in the whitelist. */
int rbl_is_whitelisted(char *name)
{
  return check_list(daemon->rbl_whitelist, name);
}

/* Returns 1 if name is in the blacklist. */
int rbl_is_blacklisted(char *name)
{
  return check_list(daemon->rbl_blacklist, name);
}


/* If name is in the whitelist or blacklist returns RBL_ACTION_PERMIT or
   RBL_ACTION_DENY, otherwise returns RBL_ACTION_UNKNOWN. */
int rbl_domainlist_action(char *name, int *log_flag)
{
  if (rbl_is_whitelisted(name))
    {
      *log_flag |= F_RBL_WHITELISTED;
      return RBL_ACTION_PERMIT;
    }
  else if (rbl_is_blacklisted(name))
    {
      *log_flag |= F_RBL_BLACKLISTED;
      return RBL_ACTION_DENY;
    }
  return RBL_ACTION_UNKNOWN;
}


/* categories is a space separated null terminated string.  Checks if any of
   the given categories are in the configured allow/deny list and returns
   RBL_ACTION_PERMIT or RBL_ACTION_DENY, or RBL_ACTION_UNKNOWN if no categories
   were in the list. */
int rbl_category_action(const unsigned char *categories, int *log_flag)
{
  /* Separate the category list on spaces */
  char categories_copy[RBL_MAX_CATSIZE];
  char *categories_p[RBL_MAX_CATCOUNT + 1];

  int i;
  int cat_i;
  char *start, *p;

  struct rbl_category_list* list;
  char **cat;

  strncpy(categories_copy, (const char*) categories, RBL_MAX_CATSIZE);

  for (i = cat_i = 0, start = p = categories_copy ; i<RBL_MAX_CATSIZE && cat_i < RBL_MAX_CATCOUNT ; ++i, ++p)
    if (*p == ' ')
      {
	*p = '\0';
	categories_p[cat_i++] = start;
	start = p+1;
      }
    else if (*p == 0)
      {
	categories_p[cat_i++] = start;
	break;
      }

  categories_p[cat_i] = NULL;

  /* Check if any of the categories were in the deny or permit list */
  for (list = daemon->rbl_categories ; list != NULL ; list = list->next)
    for (cat = categories_p ; *cat != NULL ; ++cat)
      if (strcmp(list->category_name, *cat) == 0)
	{
	  *log_flag = (list->action == RBL_ACTION_PERMIT) ?
		F_RBL_PERMITTED_CATEGORY :
		F_RBL_DENIED_CATEGORY;
	  return list->action;
	}

  return RBL_ACTION_UNKNOWN;
}


/* Appends the rbl-suffix to name and stores the result in buf.  Returns 1 on
   success or 0 if buf was too small. */
int rbl_txtname(const char *name, size_t buf_size, char *buf)
{
  size_t name_len = strlen(name);
  size_t suffix_len = strlen(daemon->rbl_suffix);
  size_t needs_dot = 1;

  if (name_len > 0 && name[name_len-1] == '.')
    needs_dot = 0;

  if (name_len + needs_dot + suffix_len + 1 > buf_size)
    return 0;

  memcpy(buf, name, name_len);
  buf += name_len;

  if (needs_dot)
    *(buf++) = '.';

  memcpy(buf, daemon->rbl_suffix, suffix_len);
  buf += suffix_len;

  *buf = '\0';

  return 1;
}


/* If action is RBL_ACTION_PERMIT, writes a log message to say the request was
   allowed.  If action is RBL_ACTION_DENY, adds blocked responses. */
void rbl_respond(int action, int log_flag,
		 char *name, int flag, int qtype,
		 struct dns_header* header, char* limit, int* trunc,
		 unsigned int nameoffset, unsigned char** ansp, unsigned short type,
		 int* ans, int* anscount)
{
  if (action == RBL_ACTION_PERMIT)
    log_query(flag | log_flag, name, NULL, NULL);
  else if (action == RBL_ACTION_DENY)
    {
      struct rbl_target_list *tgt;

      *ans = 1;
      log_query(flag | log_flag, name, NULL, NULL);

      /* Find suitable (A or AAAA) records to return instead of
	 the name's real address. */
      if (qtype == T_A)
	for (tgt = daemon->rbl_blocked_target ; tgt != NULL ; tgt = tgt->next)
	  {
	    if (tgt->type != F_IPV4)
	      continue;

	    add_resource_record(
		  header, limit, trunc, nameoffset, ansp, daemon->local_ttl,
		  NULL, type, C_IN, "4", &tgt->addr.addr.addr4);
	    *anscount += 1;
	  }
#ifdef HAVE_IPV6
      else if (qtype == T_AAAA)
	for (tgt = daemon->rbl_blocked_target ; tgt != NULL ; tgt = tgt->next)
	  {
	    if (tgt->type != F_IPV6)
	      continue;

	    add_resource_record(
		  header, limit, trunc, nameoffset, ansp, daemon->local_ttl,
		  NULL, type, C_IN, "6", &tgt->addr.addr.addr6);
	    *anscount += 1;
	  }
#endif
    }
}
