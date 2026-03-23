package services

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// ── Minecraft Java Edition server-list-ping emulator ─────────────────────────
//
// Protocol reference: https://wiki.vg/Server_List_Ping
//
// Flow:
//  1. Client → Handshake packet  (ID 0x00, next_state=1)
//  2. Client → Status Request    (ID 0x00, empty payload)
//  3. Server → Status Response   (ID 0x00, JSON payload)
//  4. Client → Ping Request      (ID 0x01, payload int64)
//  5. Server → Pong Response     (ID 0x01, echo same int64)  [optional]

// MinecraftPort is the default Minecraft Java Edition server port.
const MinecraftPort = 25565

// StartMinecraftListener binds to MinecraftPort and emulates a Java Edition
// server-list-ping handshake.
func StartMinecraftListener(isBanned IsBannedFunc, capture CaptureFunc) {
	portStr := "25565"
	addr := ":25565"

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Minecraft listener on %s failed: %v", addr, err)
		return
	}
	log.Printf("Minecraft listener on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Minecraft accept on %s: %v", addr, err)
			time.Sleep(time.Second)
			continue
		}
		go func(c net.Conn) {
			srcIP := extractConnIP(c.RemoteAddr())
			if isBanned(srcIP, portStr) {
				c.Close()
				return
			}
			clientData := handleMinecraftConn(c)
			go capture(srcIP, portStr, "tcp", clientData)
		}(conn)
	}
}

// mcReadVarInt reads a Minecraft VarInt from the connection.
func mcReadVarInt(r io.Reader) (int32, error) {
	var result int32
	var shift uint
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		b := buf[0]
		result |= int32(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
		if shift >= 35 {
			return 0, fmt.Errorf("VarInt too large")
		}
	}
}

// mcWriteVarInt encodes a VarInt into a byte slice.
func mcWriteVarInt(v int32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

// mcWriteString encodes a Minecraft protocol String (VarInt length-prefixed UTF-8).
func mcWriteString(s string) []byte {
	b := []byte(s)
	return append(mcWriteVarInt(int32(len(b))), b...)
}

// mcPacket wraps payload bytes into a framed Minecraft packet.
func mcPacket(packetID int32, payload []byte) []byte {
	idBytes := mcWriteVarInt(packetID)
	body := append(idBytes, payload...)
	return append(mcWriteVarInt(int32(len(body))), body...)
}

// mcStatusJSON builds the JSON status response that Minecraft clients display
// in the server browser.
func mcStatusJSON() string {
	type chatText struct {
		Text string `json:"text"`
	}
	type playerSample struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	type players struct {
		Max    int            `json:"max"`
		Online int            `json:"online"`
		Sample []playerSample `json:"sample"`
	}
	type version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	}
	type status struct {
		Version     version  `json:"version"`
		Players     players  `json:"players"`
		Description chatText `json:"description"`
	}

	s := status{
		Version:     version{Name: "1.20.4", Protocol: 765},
		Players:     players{Max: 20, Online: 3, Sample: []playerSample{}},
		Description: chatText{Text: "A Minecraft Server"},
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// handleMinecraftConn processes a single Minecraft client connection.
func handleMinecraftConn(c net.Conn) []byte {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	// Packet 1: Handshake
	pktLen, err := mcReadVarInt(c)
	if err != nil || pktLen <= 0 || pktLen > 512 {
		return nil
	}
	pktData := make([]byte, pktLen)
	if _, err := io.ReadFull(c, pktData); err != nil {
		return nil
	}
	if len(pktData) == 0 || pktData[0] != 0x00 {
		return pktData
	}
	clientData := pktData

	// Packet 2: Status Request
	pktLen2, err := mcReadVarInt(c)
	if err != nil || pktLen2 < 1 {
		return clientData
	}
	pktData2 := make([]byte, pktLen2)
	if _, err := io.ReadFull(c, pktData2); err != nil {
		return clientData
	}
	if len(pktData2) == 0 || pktData2[0] != 0x00 {
		return clientData
	}

	// Packet 3: Status Response
	statusJSON := mcStatusJSON()
	respPayload := mcWriteString(statusJSON)
	if _, err := c.Write(mcPacket(0x00, respPayload)); err != nil {
		return clientData
	}

	// Packets 4+5: Ping / Pong (optional)
	pingLen, err := mcReadVarInt(c)
	if err != nil || pingLen != 9 {
		return clientData
	}
	pingData := make([]byte, pingLen)
	if _, err := io.ReadFull(c, pingData); err != nil {
		return clientData
	}
	if pingData[0] != 0x01 {
		return clientData
	}
	pongPayload := pingData[1:]
	_ = binary.LittleEndian.Uint64(pongPayload)
	c.Write(mcPacket(0x01, pongPayload)) //nolint:errcheck
	return clientData
}
