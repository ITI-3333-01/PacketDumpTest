package com.austinlm.packetdump;

import static com.austinlm.packetdump.util.Logging.getLogger;
import static com.austinlm.packetdump.util.PacketUtils.formatPacket;

import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import picocli.CommandLine;
import picocli.CommandLine.Option;

/**
 * Main class
 *
 * @author austinlm
 */
public class Main implements Callable<Void> {

  /**
   * File header
   */
  private static String[] HEADER = new String[]{
      "# Packet Dump Utility by Austin Mayes\n",
      "# Created for the 2018-19 IT FLARE project\n",
      "# Started on " + new Date().toString() + "\n"
  };
  /**
   * Console logging
   */
  private final Logger logger = getLogger("Main");
  /**
   * Output file path
   */
  @Option(names = {"-o", "--out"}, required = true)
  private String outPath;
  /**
   * Name of interface selected
   */
  @Option(names = {"-i", "--interface"})
  private String interfaceName;
  /**
   * If an interface selection screen should be displayed
   */
  @Option(names = {"-c", "--choose-interface"}, description = "Pick an interface from a list")
  private boolean chooseInterface = false;
  /**
   * Set to false by a shutdown handler which ends the main packet loop.
   */
  private boolean doLoop = true;
  /**
   * Handler for incoming packets.
   */
  private PcapHandle handle;

  public static void main(String[] args) throws Exception {
    // Parse args (see above @Option s)
    // If everything works out OK, the call() method under this will be executed.
    CommandLine.call(new Main(), args);
  }

  @Override
  public Void call() throws Exception {
    // Safety check for incompetent people
    if (interfaceName == null && !chooseInterface) {
      logger.severe("Interface name not supplied and choose option disabled!");
      System.exit(0);
    }

    // Determine the interface
    PcapNetworkInterface device = getNetworkDevice();
    logger.info("You chose: " + device);

    if (device == null) {
      logger.severe("No device chosen.");
      System.exit(1);
    }

    // Create writer using supplied path
    BufferedWriter writer = setupFile();

    // Run this when the process is terminated.
    Runtime.getRuntime().addShutdownHook(new Thread(this::finish));

    // Open the device and get a handle
    int snapshotLength = 65536; // bytes
    int readTimeout = 50; // mills
    handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);

    // Filter only 443 packets using ipv4 in the tcp scope
    String filter = "tcp port 443 and ip proto \\tcp";
    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

    // Write my nice header
    for (String s : HEADER) {
      writer.write(s);
    }
    // Add some blank space
    for (int i = 0; i < 4; i++) {
      writer.write("\n");
    }

    // Main packet write loop
    while (doLoop) {
      try {
        Packet packet = handle.getNextPacketEx();
        if (packet.contains(IpV4Packet.class)) {
          writer.write(formatPacket(packet, true));
        }
      } catch (TimeoutException ignored) { // Ignore timeouts for now
      } catch (EOFException e) {
        // Print a trace, but keep going on with life since these are rare.
        e.printStackTrace();
      }
    }

    // Close the file writer
    // Can't close the packet handler here since it's needed for stats
    writer.close();

    return null;
  }

  /**
   * Construct a {@link BufferedWriter} using a file path.
   *
   * If the file already exists, the writter will be in append mode.
   *
   * If the file does not exist, it will be created and opened.
   *
   * @return writer for the specified path
   */
  private BufferedWriter setupFile() {
    File file = new File(outPath);
    if (file.exists()) {
      logger.info("File already exists... appending");
      try {
        return new BufferedWriter(new FileWriter(file, true));
      } catch (IOException e) {
        e.printStackTrace();
        System.exit(1);
      }
    } else {
      try {
        file.createNewFile();
        logger.info("Created file at " + file.getAbsolutePath());
      } catch (IOException e) {
        logger.severe("Failed to create file!");
        e.printStackTrace();
        System.exit(1);
      }
    }
    try {
      return new BufferedWriter(new FileWriter(file));
    } catch (IOException e) {
      e.printStackTrace();
      System.exit(1);
    }

    return null;
  }

  /**
   * Called when the JVM is shutting down.
   */
  private void finish() {
    // Stop the packet loop
    this.doLoop = false;

    try {
      logger.info("Shouting down...");
      Thread.sleep(400);

      // Have to get a new logger here since the main one has already been disposed.
      Logger shutdown = getLogger("Shutdown");

      // Some useful stats for fun
      PcapStat stats = handle.getStats();
      shutdown.info("Packets received: " + stats.getNumPacketsReceived());
      shutdown.info("Packets dropped: " + stats.getNumPacketsDropped());
      shutdown.info("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());

      // Have to do this after stats generation
      handle.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * Determine what networking interface card should be used for capturing packets.
   *
   * Assumes that either {@link #chooseInterface} of {@link #interfaceName} is not null.
   *
   * @return the interface for sniffing
   */
  private PcapNetworkInterface getNetworkDevice() {
    PcapNetworkInterface device = null;
    try {
      if (chooseInterface) {
        device = new NifSelector().selectNetworkInterface();
      } else {
        device = Pcaps.getDevByName(interfaceName);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return device;
  }
}
