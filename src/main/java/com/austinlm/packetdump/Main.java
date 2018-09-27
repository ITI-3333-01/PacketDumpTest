package com.austinlm.packetdump;

import static com.austinlm.packetdump.util.Logging.getLogger;

import com.austinlm.packetdump.util.FileUtils;
import com.austinlm.packetdump.util.StatsUtils;
import java.io.EOFException;
import java.io.File;
import java.net.Inet4Address;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.Builder;
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
 *
 * TODO: Sort list New file for each dump (timestamped)
 */
public class Main implements Callable<Void> {

  /**
   * Console logging
   */
  public static final Logger logger = getLogger("Main");
  /**
   * Map of source IP -> total packet length in current stats frame
   */
  private final Map<Inet4Address, AtomicInteger> ipTraffic = new HashMap<>();
  /**
   * When the current packet stat dump frame was started.
   */
  private Instant start = Instant.now();
  /**
   * Output file path
   */
  @Option(names = {"-o",
      "--out"}, description = "File to print data to. If no file is chosen, data will be printed to console.")
  private String outPath;
  private File outDir;
  /**
   * Name of interface selected
   */
  @Option(names = {"-i", "--interface"})
  private String interfaceName;
  /**
   * If an interface selection screen should be displayed
   */
  @Option(names = {"-c",
      "--choose-interface"}, description = "Pick an interface from a list", defaultValue = "false")
  private boolean chooseInterface;
  /**
   * PCAP buffer size
   */
  @Option(names = {"-b",
      "--buffer-size"}, description = "The PCAP buffer size to use.", defaultValue = "2097152")
  private int bufferSize;
  /**
   * PCAP filter
   */
  @Option(names = {"-f",
      "--filter"}, description = "The PCAP filter to use.", defaultValue = "tcp port 443 and ip proto \\tcp")
  private String filter;
  /**
   * Time (in seconds) before a new stats dump is created
   */
  @Option(names = {"-w",
      "--stats-window"}, description = "Time (in seconds) before a new stats dump is created.", defaultValue = "60")
  private int statsWindow;
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
      System.exit(1);
    }

    // Determine the interface
    PcapNetworkInterface device = getNetworkDevice();

    if (device == null) {
      logger.severe("No device chosen!");
      System.exit(1);
    }

    logger.info("You chose: " + device.getName());

    outDir = FileUtils.checkFile(this.outPath);

    // Run this when the process is terminated.
    Runtime.getRuntime().addShutdownHook(new Thread(this::finish));

    // Open the device and get a handle
    int snapshotLength = 65536; // bytes
    int readTimeout = 50; // mills
    PcapHandle.Builder builder = new Builder(device.getName());
    builder.bufferSize(bufferSize).promiscuousMode(PromiscuousMode.PROMISCUOUS)
        .timeoutMillis(readTimeout).snaplen(snapshotLength);
    handle = builder.build();

    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

    // Main packet write loop
    while (doLoop) {
      // Dump stats if now minus the window is greater than the start.
      // This is spun off on it's own thread since dumping could take a while (depending on number of packets)
      if (Instant.now().minusSeconds(statsWindow).isAfter(start)) {
        Instant finalStart = start;
        new Thread(() -> StatsUtils
            .dumpStats(finalStart, new HashMap<>(this.ipTraffic), this.outDir, this.statsWindow,
                logger)).run();
        this.ipTraffic.clear();
        start = Instant.now();
      }

      try {
        Packet packet = handle.getNextPacketEx();
        if (packet.contains(IpV4Packet.class)) {
          Inet4Address addr = packet.get(IpV4Packet.class).getHeader().getDstAddr();
          this.ipTraffic.putIfAbsent(addr, new AtomicInteger());
          this.ipTraffic.get(addr).addAndGet(packet.getHeader().length());
        }
      } catch (TimeoutException ignored) { // Ignore timeouts for now
      } catch (EOFException e) {
        // Print a trace, but keep going on with life since these are rare.
        e.printStackTrace();
      }
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
      logger.info("Shutting down...");
      Thread.sleep(400);

      // Have to get a new logger here since the main one has already been disposed.
      Logger shutdown = getLogger("Shutdown");

      // Some useful stats for fun
      PcapStat stats = handle.getStats();
      shutdown.info("Packets received: " + stats.getNumPacketsReceived());
      shutdown.info("Packets dropped: " + stats.getNumPacketsDropped());
      shutdown.info("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());

      StatsUtils.dumpStats(this.start, this.ipTraffic, this.outDir, this.statsWindow, shutdown);
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
