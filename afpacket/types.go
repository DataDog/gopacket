//go:build ignore

//go:generate sh -c "go tool cgo -godefs -- -fsigned-char types.go > types_linux.go && gofmt -w types_linux.go"

package afpacket

/*
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
*/
import "C"

const VLAN_HLEN = 4

const ETH_ALEN = C.ETH_ALEN

type TPacketHdr C.struct_tpacket_hdr

const SizeOfTPacketHdr = C.sizeof_struct_tpacket_hdr

type TPacket2Hdr C.struct_tpacket2_hdr

const SizeOfTPacket2Hdr = C.sizeof_struct_tpacket2_hdr

type TPacket3Hdr C.struct_tpacket3_hdr

const SizeOfTPacket3Hdr = C.sizeof_struct_tpacket3_hdr

type SockAddrLL C.struct_sockaddr_ll

type TPacketBlockDesc C.struct_tpacket_block_desc
type TPacketBdTs C.struct_tpacket_bd_ts
type TPacketHdrV1 C.struct_tpacket_hdr_v1
type TPacketHdrVariant1 C.struct_tpacket_hdr_variant1
