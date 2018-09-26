package com.austinlm.packetdump.util;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.Packet;

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
  public static String formatPacket(Packet packet) {
    StringBuilder pak = new StringBuilder();

    IpV4Header header = packet.get(IpV4Packet.class).getHeader();

    pak.append(header.getSrcAddr());
    pak.append(" > ");
    pak.append(header.getDstAddr());
    pak.append("\n");

    return pak.toString();
  }
}
