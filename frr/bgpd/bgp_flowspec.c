// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP FlowSpec for packet handling
 * Portions:
 *     Copyright (C) 2017 ChinaTelecom SDN Group
 *     Copyright (C) 2018 6WIND
 */

#include <zebra.h>
#include <math.h>
#include <stdint.h>

#include "prefix.h"
#include "lib_errors.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_flowspec_private.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"

struct bgp_iptable_payload {
	uint8_t ptype;
	uint8_t otype;
	uint16_t offset;
	uint8_t contlen;
	uint8_t *content;
	uint8_t *mask;
};

struct bgp_iptable_info {
	uint8_t proto;

	uint8_t family;
	uint8_t dst_prefixlen;
	uint8_t *dst_prefix;
	uint8_t src_prefixlen;
	uint8_t *src_prefix;

	uint8_t payload_num;
	struct bgp_iptable_payload *payload;

	uint32_t rate_pps;
};

static int bgp_fs_nlri_validate(uint8_t *nlri_content, uint32_t len,
				afi_t afi)
{
	uint32_t offset = 0;
	int type;
	int ret = 0, error = 0;

	while (offset < len-1) {
		type = nlri_content[offset];
		offset++;
		switch (type) {
		case FLOWSPEC_DEST_PREFIX:
		case FLOWSPEC_SRC_PREFIX:
			ret = bgp_flowspec_ip_address(
						BGP_FLOWSPEC_VALIDATE_ONLY,
						nlri_content + offset,
						len - offset, NULL, &error,
						afi, NULL);
			break;
		case FLOWSPEC_FLOW_LABEL:
			if (afi == AFI_IP)
				return -1;
			ret = bgp_flowspec_op_decode(BGP_FLOWSPEC_VALIDATE_ONLY,
						   nlri_content + offset,
						   len - offset, NULL, &error);
			break;
		case FLOWSPEC_IP_PROTOCOL:
		case FLOWSPEC_PORT:
		case FLOWSPEC_DEST_PORT:
		case FLOWSPEC_SRC_PORT:
		case FLOWSPEC_ICMP_TYPE:
		case FLOWSPEC_ICMP_CODE:
			ret = bgp_flowspec_op_decode(BGP_FLOWSPEC_VALIDATE_ONLY,
						   nlri_content + offset,
						   len - offset, NULL, &error);
			break;
		case FLOWSPEC_TCP_FLAGS:
		case FLOWSPEC_FRAGMENT:
			ret = bgp_flowspec_bitmask_decode(
						   BGP_FLOWSPEC_VALIDATE_ONLY,
						   nlri_content + offset,
						   len - offset, NULL, &error);
			break;
		case FLOWSPEC_PKT_LEN:
		case FLOWSPEC_DSCP:
			ret = bgp_flowspec_op_decode(
						BGP_FLOWSPEC_VALIDATE_ONLY,
						nlri_content + offset,
						len - offset, NULL, &error);
			break;
		case FLOWSPEC_PAYLOAD:
			ret = bgp_flowspec_payload_decode(BGP_FLOWSPEC_VALIDATE_ONLY,
						   nlri_content + offset,
						   len - offset, NULL, &error);
			break;
		default:
			error = -1;
			break;
		}
		offset += ret;
		if (error < 0)
			break;
	}
	return error;
}

static int bgp_fs_nlri_get_iptable_info(uint8_t *nlri_content, uint32_t max_len, afi_t afi, 
				struct ecommunity *ecom, struct bgp_iptable_info *iptable_info)
{
	uint32_t offset = 0;
	uint8_t type, subtype, prefix_size;
	uint8_t *pnt;
	uint8_t ptr, loop, complen;
	struct bgp_iptable_payload *comp;
	int error = 0;

	iptable_info->family = afi2family(afi);
	while (offset < max_len - 1) {
		type = nlri_content[offset];
		++offset;
		switch (type) {
		case FLOWSPEC_DEST_PREFIX:
			iptable_info->dst_prefixlen = nlri_content[offset];
			++offset;
			prefix_size = PSIZE(iptable_info->dst_prefixlen);
			if (iptable_info->family == AF_INET) {
				iptable_info->dst_prefix = realloc(iptable_info->dst_prefix, 4);
				memset(iptable_info->dst_prefix, 0, 4);
				for (int i = 0; i < prefix_size; i++)
					iptable_info->dst_prefix[i] = nlri_content[offset++];
			}
			break;
		case FLOWSPEC_SRC_PREFIX:
			iptable_info->src_prefixlen = nlri_content[offset];
			++offset;
			prefix_size = PSIZE(iptable_info->src_prefixlen);
			if (iptable_info->family == AF_INET) {
				iptable_info->src_prefix = realloc(iptable_info->src_prefix, 4);
				memset(iptable_info->src_prefix, 0, 4);
				for (int i = 0; i < prefix_size; i++)
					iptable_info->src_prefix[i] = nlri_content[offset++];
			}
			break;
		case FLOWSPEC_IP_PROTOCOL:
			/* only equal supported */
			++offset;
			iptable_info->proto = nlri_content[offset];
			++offset;
			break;
		case FLOWSPEC_PAYLOAD:
			ptr = 0;
			loop = 0;
			complen = nlri_content[offset];
			++offset;

			while (ptr < complen) {
				comp = realloc(iptable_info->payload, (loop + 1) * sizeof(struct bgp_iptable_payload));
				comp[loop].ptype = nlri_content[offset + ptr + BGP_FLOWSPEC_PAYLD_TYPE_OFFSET] >> 4;
				comp[loop].otype = nlri_content[offset + ptr + BGP_FLOWSPEC_PAYLD_TYPE_OFFSET] & 0xf;
				comp[loop].offset = ((uint16_t)nlri_content[offset + ptr + BGP_FLOWSPEC_PAYLD_OFFSET_OFFSET] << 8) | (uint16_t)nlri_content[offset + ptr + BGP_FLOWSPEC_PAYLD_OFFSET_OFFSET + 1];
				comp[loop].contlen = nlri_content[offset + ptr + BGP_FLOWSPEC_PAYLD_CONTL_OFFSET];
				comp[loop].content = malloc(comp[loop].contlen);
				comp[loop].mask = malloc(comp[loop].contlen);
				for (int i = 0; i < comp[loop].contlen; i++)
				{
					comp[loop].content[i] = nlri_content[offset + ptr + BGP_FLOWSPEC_PAYLD_HL + i];
					comp[loop].mask[i] = nlri_content[offset + ptr + BGP_FLOWSPEC_PAYLD_HL + comp[loop].contlen + i];
				}
				ptr += BGP_FLOWSPEC_PAYLD_HL + 2 * comp[loop].contlen;
				iptable_info->payload = comp;
				++loop;
			}
			iptable_info->payload_num = loop;
			offset += ptr;
			break;
		default:
			break;
		}

		if (error < 0)
			break;
	}

	iptable_info->rate_pps = 0;
	for (int i = 0; i < ecom->size; i++) {
		pnt = ecom->val + (i * ecom->unit_size);
		type = *pnt;
		++pnt;
		if (type == ECOMMUNITY_ENCODE_TRANS_EXP) {
			subtype = *pnt;
			if (subtype == ECOMMUNITY_TRAFFIC_RATE_PPS) {
				pnt += 3;
				uint32_t part;
				for (int j = 0; j < 4; j++) {
					part = *(pnt + j);
					iptable_info->rate_pps |= part << 8 * (3 - j);
				}
				break;
			}
		}
	}

	return error;
}

static void payload_to_u32(uint8_t *payload, uint8_t payload_length, uint32_t *result, uint8_t result_length)
{
	for (int i = 0; i < payload_length; i++) 
		result[i / 4] |= (uint32_t)payload[i] << (3 - (i % 4)) * 8;

}

static int bgp_iptable_update(uint8_t *nlri_content, uint32_t max_len, afi_t afi, struct ecommunity *ecom, bool withdraw)
{
	char cmd[1024];
	uint16_t ptr = 0;
	struct bgp_iptable_info *iptable_info;
	iptable_info = calloc(1, sizeof(struct bgp_iptable_info));

	ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "sudo iptables ");
	
	if (!withdraw)
		ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-A ");
	else
		ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-D ");
	
	ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "FRR_FORWARD ! -f ");

	bgp_fs_nlri_get_iptable_info(nlri_content, max_len, afi, ecom, iptable_info);

	if (iptable_info->proto == 6)
		ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-p tcp ");
	else if (iptable_info->proto == 17)
		ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-p udp ");

	if (iptable_info->family == AF_INET) {
		if (iptable_info->src_prefix != NULL) {
			ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-s %u.%u.%u.%u/%u ", 
			iptable_info->src_prefix[0], iptable_info->src_prefix[1], iptable_info->src_prefix[2], 
			iptable_info->src_prefix[3], iptable_info->src_prefixlen);
		}
		if (iptable_info->dst_prefix != NULL) {
			ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-d %u.%u.%u.%u/%u ", 
			iptable_info->dst_prefix[0], iptable_info->dst_prefix[1], iptable_info->dst_prefix[2], 
			iptable_info->dst_prefix[3], iptable_info->dst_prefixlen);
		}
	}

	const char *ip_payload_offset = "0>>22&0x3C@";
	const char *tcp_payload_offset = "0>>22&0x3C@ 12>>26&0x3C@";
	if (iptable_info->payload_num > 0) {
		ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-m u32 --u32 \"");

		uint32_t *content, *mask;
		uint8_t length, rshift;
		uint16_t begin;
		for (int i = 0; i < iptable_info->payload_num; i++) {
			if (i != 0)
				ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, " && ");

			begin = iptable_info->payload[i].offset;
			rshift = (4 - iptable_info->payload[i].contlen % 4) * 8;

			length = iptable_info->payload[i].contlen / 4;
			if (iptable_info->payload[i].contlen % 4 != 0)
				++length;
			content = calloc(length, sizeof(uint32_t));
			mask = calloc(length, sizeof(uint32_t));

			payload_to_u32(iptable_info->payload[i].content, iptable_info->payload[i].contlen, content, length);
			payload_to_u32(iptable_info->payload[i].mask, iptable_info->payload[i].contlen, mask, length);

			for (int j = 0; j < length; j++) {
				if (j != 0)
					ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, " && ");
				if (j == length - 1 && rshift != 0) {
					content[j] >>= rshift;
					mask[j] >>= rshift;
					if (iptable_info->payload[i].otype == 0) {
						ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "%u>>%u&0x%X=0x%X", j * 4 + begin, rshift, mask[j], content[j]);
					} else if (iptable_info->payload[i].otype == 1) {
						ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "%s %u>>%u&0x%X=0x%X", ip_payload_offset, j * 4 + begin, rshift, mask[j], content[j]);
					} else if (iptable_info->payload[i].otype == 2) {
						if (iptable_info->proto == 6)
							ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "%s %u>>%u&0x%X=0x%X", tcp_payload_offset, j * 4 + begin, rshift, mask[j], content[j]);
						else if (iptable_info->proto == 17)
							ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "%s %u>>%u&0x%X=0x%X", ip_payload_offset, 8 + j * 4 + begin, rshift, mask[j], content[j]);
					}
					continue;
				}

				if (iptable_info->payload[i].otype == 0) {
					ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "%u&0x%X=0x%X", j * 4 + begin, mask[j], content[j]);
				} else if (iptable_info->payload[i].otype == 1) {
					ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "%s %u&0x%X=0x%X", ip_payload_offset, j * 4 + begin, mask[j], content[j]);
				} else if (iptable_info->payload[i].otype == 2) {
					if (iptable_info->proto == 6)
						ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "%s %u&0x%X=0x%X", tcp_payload_offset, j * 4 + begin, mask[j], content[j]);
					else if (iptable_info->proto == 17)
						ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "%s %u&0x%X=0x%X", ip_payload_offset, 8 + j * 4 + begin, mask[j], content[j]);
				}
			}
			free(content);
			free(mask);
		}
		ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "\" ");
	}

	if (iptable_info->rate_pps == 0) {
		ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-j DROP");
		if (system(cmd) != 0)
			return -1;
	}
	else {
		char cmd2[1024];
		memcpy(cmd2, cmd, ptr);
		uint16_t ptr2 = ptr;

		ptr += snprintf(cmd + ptr, sizeof(cmd) - ptr, "-m limit --limit %u/s --limit-burst 1 -j ACCEPT", iptable_info->rate_pps);
		ptr2 += snprintf(cmd2 + ptr2, sizeof(cmd2) - ptr2, "-j DROP");
		if (system(cmd) != 0)
			return -1;
		if (system(cmd2) != 0)
			return -2;
	}

	free(iptable_info->dst_prefix);
	free(iptable_info->src_prefix);
	for (int i = 0; i < iptable_info->payload_num; i++) {
		free(iptable_info->payload[i].content);
		free(iptable_info->payload[i].mask);
	}
	free(iptable_info->payload);
	free(iptable_info);

	return 0;
}

int bgp_nlri_parse_flowspec(struct peer *peer, struct attr *attr,
			    struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	int psize = 0;
	struct prefix p;
	void *temp;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;

	/*
	 * All other AFI/SAFI's treat no attribute as a implicit
	 * withdraw.  Flowspec should as well.
	 */
	if (!attr)
		withdraw = true;

	if (packet->length >= FLOWSPEC_NLRI_SIZELIMIT_EXTENDED) {
		flog_err(EC_BGP_FLOWSPEC_PACKET,
			 "BGP flowspec nlri length maximum reached (%u)",
			 packet->length);
		return BGP_NLRI_PARSE_ERROR_FLOWSPEC_NLRI_SIZELIMIT;
	}

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* All FlowSpec NLRI begin with length. */
		if (pnt + 1 > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		psize = *pnt++;
		if (psize >= FLOWSPEC_NLRI_SIZELIMIT) {
			psize &= 0x0f;
			psize = psize << 8;
			psize |= *pnt++;
		}
		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim) {
			flog_err(
				EC_BGP_FLOWSPEC_PACKET,
				"Flowspec NLRI length inconsistent ( size %u seen)",
				psize);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		if (psize == 0) {
			flog_err(EC_BGP_FLOWSPEC_PACKET,
				 "Flowspec NLRI length 0 which makes no sense");
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		if (bgp_fs_nlri_validate(pnt, psize, afi) < 0) {
			flog_err(
				EC_BGP_FLOWSPEC_PACKET,
				"Bad flowspec format or NLRI options not supported");
			return BGP_NLRI_PARSE_ERROR_FLOWSPEC_BAD_FORMAT;
		}
		p.family = AF_FLOWSPEC;
		p.prefixlen = 0;
		/* Flowspec encoding is in bytes */
		p.u.prefix_flowspec.prefixlen = psize;
		p.u.prefix_flowspec.family = afi2family(afi);
		temp = XCALLOC(MTYPE_TMP, psize);
		memcpy(temp, pnt, psize);
		p.u.prefix_flowspec.ptr = (uintptr_t) temp;

		if (BGP_DEBUG(flowspec, FLOWSPEC)) {
			char return_string[BGP_FLOWSPEC_NLRI_STRING_MAX];
			char local_string[BGP_FLOWSPEC_NLRI_STRING_MAX*2+16];
			char ec_string[BGP_FLOWSPEC_NLRI_STRING_MAX];
			char *s = NULL;

			bgp_fs_nlri_get_string((unsigned char *)
					       p.u.prefix_flowspec.ptr,
					       p.u.prefix_flowspec.prefixlen,
					       return_string,
					       NLRI_STRING_FORMAT_MIN, NULL,
					       afi);
			snprintf(ec_string, sizeof(ec_string),
				 "EC{none}");
			if (attr && bgp_attr_get_ecommunity(attr)) {
				s = ecommunity_ecom2str(
					bgp_attr_get_ecommunity(attr),
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				snprintf(ec_string, sizeof(ec_string),
					 "EC{%s}",
					s == NULL ? "none" : s);

				if (s)
					ecommunity_strfree(&s);
			}
			snprintf(local_string, sizeof(local_string),
				 "FS Rx %s %s %s %s", withdraw ?
				 "Withdraw":"Update",
				 afi2str(afi), return_string,
				 attr != NULL ? ec_string : "");
			zlog_info("%s", local_string);
		}

		bgp_iptable_update((uint8_t *)p.u.prefix_flowspec.ptr, 
								p.u.prefix_flowspec.prefixlen, 
								afi, bgp_attr_get_ecommunity(attr), withdraw);
		/* Process the route. */
		if (!withdraw) {
			bgp_update(peer, &p, 0, attr, afi, safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				   NULL, 0, 0, NULL);
		} else {
			bgp_withdraw(peer, &p, 0, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0, NULL);
		}

		XFREE(MTYPE_TMP, temp);
	}
	return BGP_NLRI_PARSE_OK;
}
