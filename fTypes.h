//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2021, fmad engineering llc
//
// The MIT License (MIT) see LICENSE file for details
//
//---------------------------------------------------------------------------------------------

#ifndef __F_TYPES_H__
#define __F_TYPES_H__

typedef unsigned int		bool;
#define true				1
#define false				0

typedef unsigned char		u8;
typedef char				s8;

typedef unsigned short		u16;
typedef short				s16;

typedef unsigned int		u32;
typedef int					s32;

typedef unsigned long long	u64;
typedef long long			s64;

typedef struct
{
	u32				magic;
	u16				major;
	u16				minor;
	u32				timezone;
	u32				sigflag;
	u32				snaplen;
	u32				link;

} __attribute__((packed)) PCAPHeader_t;

typedef struct
{
	u32				sec;				// time stamp sec since epoch
	u32				nsec;				// nsec fraction since epoch

	u32				length_capture;	// captured length, inc trailing / aligned data
	u32				length_wire;		// length on the wire

} __attribute__((packed)) PCAPPacket_t;

#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4

// --------------------------------------------------------------------------------
/** ERF type:
 *  https://wiki.wireshark.org/ERF
 */
typedef struct erf_pkt {
	u64  ts;		/**< ERF timestamp */
	u8   type;		/**< GPP record type */
	u8   flags;	/**< Flags */
	u16  rlen;		/**< Record len (capture+framing) */
	u16  lctr;		/**< Loss counter or color field */
	u16  wlen;		/**< Wire length */
	// TODO:
	// Extension header/s are present if bit 7 of the type field is '1'.
	// There can be more than one Extension header attached to a ERF record.
} __attribute__((packed)) ERFPacket_t;
static_assert(sizeof(ERFPacket_t) == 16, "ERF size");

#define ERF_TYPE_ETH 2

static inline u32 swap32(const u32 a)
{
	return (((a>>24)&0xFF)<<0) | (((a>>16)&0xFF)<<8) | (((a>>8)&0xFF)<<16) | (((a>>0)&0xFF)<<24);
}

static inline u16 swap16(const u16 a)
{
	return (((a>>8)&0xFF)<<0) | (((a>>0)&0xFF)<<8);
}

static inline u64 swap64(const u64 a)
{
	return swap32(a>>32ULL) | ( (u64)swap32(a) << 32ULL);
}

#endif
