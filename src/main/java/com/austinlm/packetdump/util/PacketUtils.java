package com.austinlm.packetdump.util;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;

/**
 * Packet formatting utils
 *
 * @author austinlm
 */
public class PacketUtils {

  /**
   * Format a packet for logging/output.
   *
   * @param packet to format
   * @return the human-readable packet
   */
  public static String formatPacket(Packet packet, boolean port) {
    StringBuilder pak = new StringBuilder();

    IpV4Header header = packet.get(IpV4Packet.class).getHeader();
    TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();

    pak.append(header.getSrcAddr());
    if (port) {
      pak.append(" : ");
      pak.append(tcpHeader.getSrcPort());
    }
    pak.append(" > ");
    pak.append(header.getDstAddr());
    if (port) {
      pak.append(" : ");
      pak.append(tcpHeader.getDstPort());
    }
    pak.append("\n");

    return pak.toString();
  }
}
