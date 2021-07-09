#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>

#include "fTypes.h"

u32 t_scale = 1;
u32 erf_eth_pad[2] = {0, 0};

void write_erf(PCAPPacket_t *pcap_pkt, u8 *payload, size_t payload_len)
{
	FILE *output_file = stdout;

	// Writes 1 PCAP packet + payload to stdout as an ERF record
	ERFPacket_t erf = { 0 };

	// Timestamp is a 64 bit fixed point.
	// From the docs:
	// "The lower 32-bits contain the binary fraction of the second allowing an
	// ultimate resolution of approximately 233 picoseconds."
	u64 TS_low = ((u64) (pcap_pkt->nsec * t_scale) << 32) / 1000 / 1000 / 1000;

	// The high 32-bits contain the integer number of seconds since the start of
	// time (unix epoch time).
	u64 TS = ((u64) pcap_pkt->sec << 32) | (
		(u64) TS_low);

	// Copy over PCAP details to ERF
	erf.ts = TS;
	erf.type = ERF_TYPE_ETH;
	erf.flags = 0;
	erf.rlen = swap16(sizeof(ERFPacket_t) + 2 + payload_len);
	erf.lctr = 0;
	erf.wlen = swap16(pcap_pkt->length_wire);

	// Write ERF
	size_t wlen = fwrite(&erf, 1, sizeof(ERFPacket_t), output_file);
	assert(wlen == sizeof(ERFPacket_t));
	// 2 bytes null padding
	wlen = fwrite(&erf_eth_pad, 1, 2, output_file);
	assert(wlen == 2);
	// Write payload
	wlen = fwrite(payload, 1, payload_len, output_file);
	assert(wlen = payload_len);
}

int main()
{
	FILE *input_file = stdin;

	// read header
	PCAPHeader_t file_header;
	int rlen = fread(&file_header, 1, sizeof(file_header), input_file);
	if (rlen != sizeof(file_header))
	{
		fprintf(stderr, "Failed to read pcap header\n");
		return -1;
	}
	if (file_header.magic == PCAPHEADER_MAGIC_USEC) t_scale = 1000;

	if (file_header.magic != PCAPHEADER_MAGIC_NANO && file_header.magic != PCAPHEADER_MAGIC_USEC)
	{
		fprintf(stderr, "Invalid PCAP format %08x\n", file_header.magic);
		return -1;
	}

	u32 cnt = 0;
	while (!feof(input_file))
	{

		PCAPPacket_t pcap_pkt = { 0 };

		// Read PCAP packet header
		int rlen = fread(&pcap_pkt, 1, sizeof(PCAPPacket_t), input_file);
		if (rlen != sizeof(PCAPPacket_t)) break;

		// validate size
		if ((pcap_pkt.length_capture == 0) || (pcap_pkt.length_capture > 128*1024))
		{
			fprintf(stderr, "Invalid packet length: %i\n", pcap_pkt.length_capture);
			break;
		}

		// Read payload
		u8 *payload = malloc(pcap_pkt.length_capture);
		rlen = fread(payload, 1, pcap_pkt.length_capture, input_file);
		if (rlen != pcap_pkt.length_capture)
		{
			fprintf(stderr, "payload read fail %i expect %i\n", rlen, pcap_pkt.length_capture);
			break;
		}

		// Write PCAP header + payload as ERF record
		write_erf(&pcap_pkt, payload, rlen);
		free(payload);

		cnt++;
	}

	fprintf(stderr, "Converted %u PCAP packets to ERF\n", cnt);
}
