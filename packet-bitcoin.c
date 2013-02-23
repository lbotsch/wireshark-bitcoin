/* packet-bitcoin.c
 * Routines for bitcoin dissection
 * Copyright 2011, Christian Svensson <blue@cmd.nu>
 * Bitcoin address: 15Y2EN5mLnsTt3CZBfgpnZR5SeLwu7WEHz
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/strutil.h>

#include <epan/dissectors/packet-tcp.h>

#define BITCOIN_PORT 8333


/*
 * Minimum bitcoin identification header.
 * - Magic - 4 bytes
 * - Command - 12 bytes
 * - Payload length - 4 bytes
 */
#define BITCOIN_HEADER_LENGTH 4+12+4

static int proto_bitcoin = -1;
static dissector_handle_t dissector_handle;

static gint hf_bitcoin_magic = -1;
static gint hf_bitcoin_command = -1;
static gint hf_bitcoin_length = -1;
static gint hf_bitcoin_checksum = -1;

/* version message */
static gint hf_bitcoin_msg_version = -1;
static gint hf_msg_version_version = -1;
static gint hf_msg_version_services = -1;
static gint hf_msg_version_timestamp = -1;
static gint hf_msg_version_addr_me = -1;
static gint hf_msg_version_addr_you = -1;
static gint hf_msg_version_nonce = -1;
static gint hf_msg_version_subver = -1;
static gint hf_msg_version_start_height = -1;

/* addr message */
static gint hf_bitcoin_msg_addr = -1;
static gint hf_msg_addr_address = -1;
static gint hf_msg_addr_timestamp = -1;

/* inv message */
static gint hf_bitcoin_msg_inv = -1;
static gint hf_msg_inv_type = -1;
static gint hf_msg_inv_hash = -1;

/* getdata message */
static gint hf_bitcoin_msg_getdata = -1;
static gint hf_msg_getdata_type = -1;
static gint hf_msg_getdata_hash = -1;

/* getblocks message */
static gint hf_bitcoin_msg_getblocks = -1;
static gint hf_msg_getblocks_start = -1;
static gint hf_msg_getblocks_stop = -1;

/* getheaders message */
static gint hf_bitcoin_msg_getheaders = -1;
static gint hf_msg_getheaders_start = -1;
static gint hf_msg_getheaders_stop = -1;

/* tx message */
static gint hf_bitcoin_msg_tx = -1;
static gint hf_msg_tx_version = -1;
static gint hf_msg_tx_in = -1;
static gint hf_msg_tx_in_prev_output = -1;
static gint hf_msg_tx_in_sig_script = -1;
static gint hf_msg_tx_in_seq = -1;
static gint hf_msg_tx_outp_hash = -1;
static gint hf_msg_tx_outp_index = -1;
static gint hf_msg_tx_out = -1;
static gint hf_msg_tx_out_value = -1;
static gint hf_msg_tx_out_script = -1;
static gint hf_msg_tx_lock_time = -1;

/* block message */
static gint hf_bitcoin_msg_block = -1;
static gint hf_msg_block_version = -1;
static gint hf_msg_block_prev_block = -1;
static gint hf_msg_block_merkle_root = -1;
static gint hf_msg_block_time = -1;
static gint hf_msg_block_bits = -1;
static gint hf_msg_block_nonce = -1;

/* services */
static gint hf_services_network = -1;

/* address */
static gint hf_address_services = -1;
static gint hf_address_address = -1;
static gint hf_address_port = -1;


static gint ett_bitcoin = -1;
static gint ett_bitcoin_msg = -1;
static gint ett_services = -1;
static gint ett_address = -1;
static gint ett_addr_list = -1;
static gint ett_inv_list = -1;
static gint ett_getdata_list = -1;
static gint ett_getblocks_list = -1;
static gint ett_getheaders_list = -1;
static gint ett_tx_in_list = -1;
static gint ett_tx_in_outp = -1;
static gint ett_tx_out_list = -1;

static const value_string inv_types[] =
{
  { 0, "ERROR" },
  { 1, "MSG_TX" },
  { 2, "MSG_BLOCK" },
  { 0, NULL }
};

static value_string_ext inv_type_ext = VALUE_STRING_EXT_INIT(inv_types);

#define BTC_CHECK_BOUNDS(ti,size,name) \
  if((guint64)tvb_reported_length_remaining(tvb, offset) < size)\
  { \
    expert_add_info_format(pinfo,ti, PI_MALFORMED, PI_ERROR, \
        "Boundary check " name " failed: requires %" G_GINT64_MODIFIER \
        "u bytes", (guint64)size); \
    return -1; \
  } 

#define BTC_CHECK_LOOP(ti,size,cnt,name) \
  BTC_CHECK_BOUNDS(ti,(size)*(cnt),name)

#define BTC_CHECK_VARINT(rti,ret) \
  if(ret < 0) \
  { \
    expert_add_info_format(pinfo,rti, PI_MALFORMED, PI_ERROR, \
        "Boundary check failed while reading variable integer"); \
    return -1; \
  }
  
static guint get_bitcoin_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 length;
  length = BITCOIN_HEADER_LENGTH;

  if(tvb_memeql(tvb, offset+4, "version", 7) != 0 &&
      tvb_memeql(tvb, offset+4, "verack", 6) != 0)
  {
    /* add checksum field */
    length += 4;
  }

  /* add payload length */
  length += tvb_get_letohl(tvb, offset+16);

  return length;
}

/**
 * Create a services sub-tree for bit-by-bit display
 */
static proto_tree *create_services_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;
  guint64 services;

  tree = proto_item_add_subtree(ti, ett_services);

  /* start of services */
  /* NOTE:
   *  - 2011-06-05
   *    Currently the boolean tree only supports a maximum of 
   *    32 bits - so we split services in two
   */
  services = tvb_get_letoh64(tvb, offset);

  /* service = NODE_NETWORK */
  proto_tree_add_boolean(tree, hf_services_network, tvb, offset, 4, (guint32)services);

  /* end of services */

  return tree;
}

/**
 * Create a sub-tree and fill it with a net_addr structure
 */
static proto_tree *create_address_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;

  tree = proto_item_add_subtree(ti, ett_address);

  /* services */
  ti = proto_tree_add_item(tree, hf_address_services, tvb, offset, 8, ENC_BIG_ENDIAN);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  /* IPv6 address */
  proto_tree_add_item(tree, hf_address_address, tvb, offset, 16, ENC_BIG_ENDIAN); 
  offset += 16;

  /* port */
  proto_tree_add_item(tree, hf_address_port, tvb, offset, 2, ENC_BIG_ENDIAN); 

  return tree;
}

/**
 * Extract a variable length integer from a tvbuff
 */
static gint get_varint(tvbuff_t *tvb, const gint offset, gint *length, guint64 *ret)
{
  guint64 value;
  gint remain;

  remain = tvb_length_remaining(tvb, offset);
  if(remain < 1)
    return -1;

  /* calculate variable length */
  value = tvb_get_guint8(tvb, offset);
  if(value < 0xfd)
  {
    *length = 1;
    *ret = value;
    return 0;
  }

  if(value == 0xfd && remain >= 3)
  {
    *length = 3;
    *ret = tvb_get_letohs(tvb, offset+1);
    return 0;
  }
  else if(value == 0xfe && remain >= 5)
  {
    *length = 5;
    *ret = tvb_get_letohl(tvb, offset+1);
    return 0;
  }
  else if(remain >= 9)
  {
    *length = 9;
    *ret = tvb_get_letoh64(tvb, offset+1);
    return 0;
  }
  
  /* could not get varint */
  return -1;
}

/**
 * Handler for version messages
 */
static guint32 dissect_bitcoin_msg_version(tvbuff_t *tvb, packet_info *pinfo _U_, 
    proto_tree *tree)
{
  proto_item *ti;
  gint subver_length;
  guint32 version;
  guint32 offset = 0;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_version, tvb, offset, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  BTC_CHECK_BOUNDS(ti, 4+8+8+26, "Version header");

  version = tvb_get_letohl(tvb, offset);

  proto_tree_add_item(tree, hf_msg_version_version, tvb, offset, 4, ENC_BIG_ENDIAN); 
  offset += 4;

  ti = proto_tree_add_item(tree, hf_msg_version_services, tvb, offset, 8, ENC_BIG_ENDIAN);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  proto_tree_add_item(tree, hf_msg_version_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN); 
  offset += 8;

  ti = proto_tree_add_item(tree, hf_msg_version_addr_me, tvb, offset, 26, ENC_BIG_ENDIAN);
  create_address_tree(tvb, ti, offset);
  offset += 26;

  if(version >= 106)
  {
    BTC_CHECK_BOUNDS(ti, 26+8+1, "Version header (version >= 106)");

    ti = proto_tree_add_item(tree, hf_msg_version_addr_you, tvb, offset, 26, ENC_BIG_ENDIAN); 
    create_address_tree(tvb, ti, offset);
    offset += 26;

    proto_tree_add_item(tree, hf_msg_version_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* find null terminated subver */
    subver_length = 0;
    subver_length = tvb_strsize(tvb, offset);
    proto_tree_add_item(tree, hf_msg_version_subver, tvb, offset, subver_length, ENC_BIG_ENDIAN);
    offset += subver_length;

    if(version >= 209)
    {
      BTC_CHECK_BOUNDS(ti, 4, "Version header (version >= 209)");
      proto_tree_add_item(tree, hf_msg_version_start_height, tvb, offset, 4, ENC_BIG_ENDIAN); 
      offset += 4;
    }
  }

  return offset;
}

/**
 * Handler for address messages
 */
static guint32 dissect_bitcoin_msg_addr(tvbuff_t *tvb, packet_info *pinfo _U_, 
    proto_tree *tree)
{
  proto_item *ti;
  gint count_length;
  guint64 count;
  guint32 offset = 0;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_addr, tvb, offset, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);
  
  BTC_CHECK_VARINT(ti, get_varint(tvb, offset, &count_length, &count));
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Count: %" G_GINT64_MODIFIER "u", count); 
  offset += count_length;

  BTC_CHECK_LOOP(ti, 30, count, "Address array bounds");

  for(; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_item(tree, hf_msg_addr_address, tvb, offset, 30, ENC_LITTLE_ENDIAN);
    subtree = create_address_tree(tvb, ti, offset+4);

    proto_tree_add_item(subtree, hf_msg_addr_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 26;
    offset += 4;
  }

  return offset;
}

/**
 * Handler for inventory messages
 */
static guint32 dissect_bitcoin_msg_inv(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree)
{
  proto_item *ti;
  gint count_length;
  guint64 count;
  guint32 offset = 0;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_inv, tvb, offset, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);
  
  BTC_CHECK_VARINT(ti, get_varint(tvb, offset, &count_length, &count));
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Count: %" G_GINT64_MODIFIER "u", count); 
  offset += count_length;

  BTC_CHECK_LOOP(ti, 36, count, "Inventory array bounds");

  for(; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_text(tree, tvb, offset, 36, "Inventory vector");
    subtree = proto_item_add_subtree(ti, ett_inv_list);

    proto_tree_add_item(subtree, hf_msg_inv_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_msg_inv_hash, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;
  }

  return offset;
}

/**
 * Handler for getdata messages
 */
static guint32 dissect_bitcoin_msg_getdata(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree)
{
  proto_item *ti;
  gint count_length;
  guint64 count;
  guint32 offset = 0;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_getdata, tvb, offset, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);
 
  BTC_CHECK_VARINT(ti, get_varint(tvb, offset, &count_length, &count));
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Count: %" G_GINT64_MODIFIER "u", count); 
  offset += count_length;

  BTC_CHECK_LOOP(ti, 36, count, "Inventory array bounds");

  for(; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_text(tree, tvb, offset, 36, "Inventory vector");
    subtree = proto_item_add_subtree(ti, ett_getdata_list);

    proto_tree_add_item(subtree, hf_msg_getdata_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_msg_getdata_hash, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;
  }

  return offset;
}

/**
 * Handler for getblocks messages
 */
static guint32 dissect_bitcoin_msg_getblocks(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree)
{
  proto_item *ti;
  gint count_length;
  guint64 count;
  guint32 offset = 0;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_getblocks, tvb, offset, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);
  
  BTC_CHECK_BOUNDS(ti, 5, "Getblocks message");

  /* why the protcol version is sent here nobody knows */
  proto_tree_add_item(tree, hf_msg_version_version, tvb, offset, 4, ENC_BIG_ENDIAN); 
  offset += 4;

  BTC_CHECK_VARINT(ti, get_varint(tvb, offset, &count_length, &count));
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Count: %" G_GINT64_MODIFIER "u", count); 
  offset += count_length;

  BTC_CHECK_LOOP(ti, 32, count, "Blocks array bounds");

  for(; count > 0; count--)
  {
    proto_tree_add_item(tree, hf_msg_getblocks_start, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;
  }

  BTC_CHECK_BOUNDS(ti, 32, "Stop block");

  proto_tree_add_item(tree, hf_msg_getblocks_stop, tvb, offset, 32, ENC_BIG_ENDIAN);
  return offset + 32;
}

/**
 * Handler for getheaders messages
 * UNTESTED
 */
static guint32 dissect_bitcoin_msg_getheaders(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree)
{
  proto_item *ti;
  gint count_length;
  guint64 count;
  guint32 offset = 0;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_getheaders, tvb, offset, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);
  
  BTC_CHECK_VARINT(ti, get_varint(tvb, offset, &count_length, &count));
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Count: %" G_GINT64_MODIFIER "u", count); 
  offset += count_length;

  BTC_CHECK_LOOP(ti, 32, count, "Blocks array bounds");
  for(; count > 0; count--)
  {
    proto_tree_add_item(tree, hf_msg_getheaders_start, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;
  }

  BTC_CHECK_BOUNDS(ti, 32, "Stop block");
  proto_tree_add_item(tree, hf_msg_getheaders_stop, tvb, offset, 32, ENC_BIG_ENDIAN);
  return offset + 32;
}

/**
 * Handler for tx messages
 */
static guint32 dissect_bitcoin_msg_tx(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree)
{
  proto_item *rti;
  gint count_length;
  guint64 in_count;
  guint64 out_count;
  guint32 offset = 0;

  rti = proto_tree_add_item(tree, hf_bitcoin_msg_tx, tvb, offset, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(rti, ett_bitcoin_msg);

  BTC_CHECK_BOUNDS(rti, 4, "Tx version");
 
  proto_tree_add_item(tree, hf_msg_tx_version, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
 
  BTC_CHECK_VARINT(rti, get_varint(tvb, offset, &count_length, &in_count));
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Input count: %" G_GINT64_MODIFIER "u", in_count); 
  offset += count_length;

  BTC_CHECK_LOOP(rti, 41, in_count, "Transaction input array")

  for(; in_count > 0; in_count--)
  {
    proto_tree *subtree;
    proto_tree *prevtree;
    proto_item *ti;
    proto_item *pti;
    guint64 script_length;

    BTC_CHECK_VARINT(rti, get_varint(tvb, offset+36, &count_length, &script_length));
    BTC_CHECK_BOUNDS(rti, 40 + count_length + script_length, "Transaction input");

    ti = proto_tree_add_item(tree, hf_msg_tx_in, tvb, offset, 
        40+count_length+script_length, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(ti, ett_tx_in_list);

    /* previous output */
    pti = proto_tree_add_item(subtree, hf_msg_tx_in_prev_output, tvb, offset, 36, ENC_BIG_ENDIAN);
    prevtree = proto_item_add_subtree(pti, ett_tx_in_outp);

    proto_tree_add_item(prevtree, hf_msg_tx_outp_hash, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;
    
    proto_tree_add_item(prevtree, hf_msg_tx_outp_index, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* end previous output */

    offset += count_length;

    proto_tree_add_item(subtree, hf_msg_tx_in_sig_script, tvb, offset, script_length, ENC_BIG_ENDIAN);
    offset += script_length;

    proto_tree_add_item(subtree, hf_msg_tx_in_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
  }

  BTC_CHECK_VARINT(rti, get_varint(tvb, offset, &count_length, &out_count));
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Output count: %" G_GINT64_MODIFIER "u", out_count); 
  offset += count_length;

  BTC_CHECK_LOOP(rti, 9, out_count, "Transaction output array")

  for(; out_count > 0; out_count--)
  {
    proto_item *ti;
    proto_tree *subtree;
    guint64 script_length;

    BTC_CHECK_VARINT(rti, get_varint(tvb, offset+8, &count_length, &script_length));

    BTC_CHECK_BOUNDS(rti, 8 + count_length + script_length, "Transaction output");

    ti = proto_tree_add_item(tree, hf_msg_tx_out, tvb, offset, 
        8+script_length+count_length, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(ti, ett_tx_out_list);

    proto_tree_add_item(subtree, hf_msg_tx_out_value, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    offset += count_length;

    proto_tree_add_item(subtree, hf_msg_tx_out_script, tvb, offset, script_length, ENC_BIG_ENDIAN);
    offset += script_length;
  }

  BTC_CHECK_BOUNDS(rti, 4, "Block lock");

  proto_tree_add_item(tree, hf_msg_tx_lock_time, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* needed for block nesting */
  proto_item_set_len(rti, offset);

  return offset;
}

/**
 * Handler for block messages
 */
static guint32 dissect_bitcoin_msg_block(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree)
{
  proto_item *ti;
  gint count_length;
  guint64 count;
  guint32 offset = 0;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_block, tvb, offset, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_block_version, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_block_prev_block, tvb, offset, 32, ENC_BIG_ENDIAN);
  offset += 32;

  proto_tree_add_item(tree, hf_msg_block_merkle_root, tvb, offset, 32, ENC_BIG_ENDIAN);
  offset += 32;

  proto_tree_add_item(tree, hf_msg_block_time, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
 
  proto_tree_add_item(tree, hf_msg_block_bits, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_block_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
 
  BTC_CHECK_VARINT(ti, get_varint(tvb, offset, &count_length, &count));
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Number of transaction: %" G_GINT64_MODIFIER "u", count); 
  offset += count_length;

  for(; count > 0; count--)
  {
    tvbuff_t *tvb_sub;
    guint32 tx_offset;

    tvb_sub = tvb_new_subset_remaining(tvb, offset);
    tx_offset = dissect_bitcoin_msg_tx(tvb_sub, pinfo, tree);

    /* check for errors */
    if(tx_offset == (guint32)-1)
      return -1;

    offset += tx_offset;
  }

  return offset;
}

/**
 * Handler for unimplemented or payload-less messages
 */
static guint32 dissect_bitcoin_msg_empty(tvbuff_t *tvb _U_, packet_info *pinfo _U_,
    proto_tree *tree _U_)
{
  return 0;
}

typedef guint32 (*msg_dissector_func_t)(tvbuff_t *tvb, packet_info *pinfo, 
    proto_tree *tree);

typedef struct msg_dissector
{ 
  const gchar *command;
  msg_dissector_func_t function;
} msg_dissector_t;

static msg_dissector_t msg_dissectors[] =
{
  {"version", dissect_bitcoin_msg_version},
  {"addr", dissect_bitcoin_msg_addr},
  {"inv", dissect_bitcoin_msg_inv},
  {"getdata", dissect_bitcoin_msg_getdata},
  {"getblocks", dissect_bitcoin_msg_getblocks},
  {"getheaders", dissect_bitcoin_msg_getheaders},
  {"tx", dissect_bitcoin_msg_tx},
  {"block", dissect_bitcoin_msg_block},

  /* messages with no payload */
  {"verack", dissect_bitcoin_msg_empty},
  {"getaddr", dissect_bitcoin_msg_empty},
  {"block", dissect_bitcoin_msg_empty},
  {"ping", dissect_bitcoin_msg_empty},

  /* messages not implemented */
  {"headers", dissect_bitcoin_msg_empty},
  {"checkorder", dissect_bitcoin_msg_empty},
  {"submitorder", dissect_bitcoin_msg_empty},
  {"reply", dissect_bitcoin_msg_empty},
  {"alert", dissect_bitcoin_msg_empty}
};

static void dissect_bitcoin_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  guint32 i;
  guint32 offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bitcoin");

  ti = proto_tree_add_item(tree, proto_bitcoin, tvb, 0, -1, ENC_LITTLE_ENDIAN);
  tree = proto_item_add_subtree(ti, ett_bitcoin);

  /* add basic protocol data */
  proto_tree_add_item(tree, hf_bitcoin_magic, tvb, 0, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_bitcoin_command, tvb, 4, 12, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_bitcoin_length, tvb, 16, 4, ENC_BIG_ENDIAN);

  offset = 20;

  if(tvb_memeql(tvb, 4, "version", 7) != 0 &&
      tvb_memeql(tvb, 4, "verack", 6) != 0)
  {
    /* add checksum field */
    if((guint64)tvb_reported_length_remaining(tvb, offset) < 4)
    { 
      expert_add_info_format(pinfo,ti, PI_MALFORMED, PI_ERROR, 
          "Packet checksum missing");
      return;
    } 

    proto_tree_add_item(tree, hf_bitcoin_checksum, tvb, 20, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* TODO: verify checksum? */
  }

  /* handle command specific message part */
  for(i = 0; i < array_length(msg_dissectors); i++)
  {
    if(tvb_memeql(tvb, 4, msg_dissectors[i].command,
          strlen(msg_dissectors[i].command)) == 0)
    {
      tvbuff_t *tvb_sub;

      col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", msg_dissectors[i].command);

      tvb_sub = tvb_new_subset_remaining(tvb, offset);
      msg_dissectors[i].function(tvb_sub, pinfo, tree);
      return;
    }
  }

  /* no handler found */
  col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "[unknown command]");

  expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Unknown command");
}


static void dissect_bitcoin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  col_clear(pinfo->cinfo, COL_INFO);
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, BITCOIN_HEADER_LENGTH, 
      get_bitcoin_pdu_length, dissect_bitcoin_tcp_pdu);
}

void proto_register_bitoin()
{
  static hf_register_info hf[] = {
    { &hf_bitcoin_magic,
      { "Packet magic", "bitcoin.magic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_bitcoin_command,
      { "Command name", "bitcoin.command", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_bitcoin_length,
      { "Payload Length", "bitcoin.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bitcoin_checksum,
      { "Payload checksum", "bitcoin.checksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },

    /* version message */
    { &hf_bitcoin_msg_version,
      { "Version message", "bitcoin.version", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_version,
      { "Protocol version", "bitcoin.version.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_services,
      { "Node services", "bitcoin.version.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_version_addr_me,
      { "Address of emmitting node", "bitcoin.version.addr_me", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_version_addr_you,
      { "Address as seen by the emitting node", "bitcoin.version.addr_you", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_version_timestamp,
      { "Node timestamp", "bitcoin.version.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_nonce,
      { "Random nonce", "bitcoin.version.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_subver,
      { "Sub-version string", "bitcoin.version.subver", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_start_height,
      { "Block start height", "bitcoin.version.start_height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* addr message */
    { &hf_bitcoin_msg_addr,
      { "Address message", "bitcoin.addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_addr_address,
      { "Address", "bitcoin.addr.address", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_addr_timestamp,
      { "Address timestamp", "bitcoin.addr.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
    }, 

    /* inv message */
    { &hf_bitcoin_msg_inv,
      { "Inventory message", "bitcoin.inv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_inv_type,
      { "Type", "bitcoin.inv.type", FT_UINT32, BASE_DEC|BASE_EXT_STRING, &inv_type_ext, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_inv_hash,
      { "Data hash", "bitcoin.inv.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 

    /* getdata message */
    { &hf_bitcoin_msg_getdata,
      { "Getdata message", "bitcoin.getdata", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_getdata_type,
      { "Type", "bitcoin.getdata.type", FT_UINT32, BASE_DEC|BASE_EXT_STRING, &inv_type_ext, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_getdata_hash,
      { "Data hash", "bitcoin.getdata.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 

    /* getblocks message */
    { &hf_bitcoin_msg_getblocks,
      { "Getdata message", "bitcoin.getblocks", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_getblocks_start,
      { "Starting hash", "bitcoin.getblocks.hash_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_getblocks_stop,
      { "Stopping hash", "bitcoin.getblocks.hash_stop", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 

    /* getheaders message */
    { &hf_bitcoin_msg_getheaders,
      { "Getheaders message", "bitcoin.getheaders", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_getheaders_start,
      { "Starting hash", "bitcoin.getheaders.hash_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_getheaders_stop,
      { "Stopping hash", "bitcoin.getheaders.hash_stop", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 

    /* tx message */
    { &hf_bitcoin_msg_tx,
      { "Tx message", "bitcoin.tx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_tx_version,
      { "Transaction version", "bitcoin.tx.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }, 
    /* tx message - input */
    { &hf_msg_tx_in,
      { "Transaction input", "bitcoin.tx.in", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_tx_in_prev_output,
      { "Previous output", "bitcoin.tx.in.prev_output", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_tx_outp_hash,
      { "Hash", "bitcoin.tx.in.prev_output.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_tx_outp_index,
      { "Index", "bitcoin.tx.in.prev_output.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_tx_in_sig_script,
      { "Signature script", "bitcoin.tx.in.sig_script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_tx_in_seq,
      { "Sequence", "bitcoin.tx.in.seq", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }, 
    /* tx message - output */ 
    { &hf_msg_tx_out,
      { "Transaction output", "bitcoin.tx.out", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_tx_out_value,
      { "Value", "bitcoin.tx.out.value", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_tx_out_script,
      { "Script", "bitcoin.tx.out.script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_tx_lock_time,
      { "Block lock time or block ID", "bitcoin.tx.lock_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }, 

    /* block message */
    { &hf_bitcoin_msg_block,
      { "Block message", "bitcoin.block", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_block_version,
      { "Block version", "bitcoin.block.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_block_prev_block,
      { "Previous block", "bitcoin.block.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_block_merkle_root,
      { "Merkle root", "bitcoin.block.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_block_time,
      { "Block timestamp", "bitcoin.block.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_block_bits,
      { "Bits", "bitcoin.block.merkle_root", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_block_nonce,
      { "Nonce", "bitcoin.block.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }, 

    /* services */
    { &hf_services_network,
      { "Network node", "bitcoin.services.network", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x1, NULL, HFILL }
    }, 

    /* address */
    { &hf_address_services,
      { "Node services", "bitcoin.address.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_address_address,
      { "Node address", "bitcoin.address.address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_address_port,
      { "Node port", "bitcoin.address.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    } 
  };

  static gint *ett[] = {
    &ett_bitcoin,
    &ett_bitcoin_msg,
    &ett_services,
    &ett_address,
    &ett_addr_list,
    &ett_inv_list,
    &ett_getdata_list,
    &ett_getblocks_list,
    &ett_getheaders_list,
    &ett_tx_in_list,
    &ett_tx_in_outp,
    &ett_tx_out_list,
  };

  proto_bitcoin = proto_register_protocol( "Bitcoin protocol", "Bitcoin",
      "bitcoin");

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_bitcoin, hf, array_length(hf));

  register_dissector("bitcoin.tcp", dissect_bitcoin, proto_bitcoin);

}

void proto_reg_handoff_bitcoin()
{
  dissector_handle = find_dissector("bitcoin.tcp");

  /* TODO: identify on magic */
  dissector_add_uint("tcp.port", BITCOIN_PORT, dissector_handle);
}

