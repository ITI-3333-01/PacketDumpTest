package com.austinlm.packetdump.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet4Address;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.annotation.Nullable;

public class StatsUtils {

  private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yy-MM-dd-HH-mm-ss");

  public static void dumpStats(Instant start, Map<Inet4Address, AtomicInteger> ipTraffic,
      @Nullable File outDir, int statsWindow, Logger logger) {
    if (outDir != null) {
      try {
        Date when = new Date(start.toEpochMilli());
        String name = "stats" + statsWindow + "_" + DATE_FORMAT.format(when) + ".almstat";
        FileWriter writer = FileUtils.createAndWrite(outDir, name);
        writer.write(statsString(ipTraffic));
        logger.info("Stats dumped to " + Paths.get(outDir.getAbsolutePath(), name).toString());
        writer.flush();
        writer.close();
      } catch (IOException e) {
        logger.severe("Failed to write to output file!");
        e.printStackTrace();
        System.exit(1);
      }
    } else {
      logger.info(statsString(ipTraffic));
    }
  }

  public static String statsString(Map<Inet4Address, AtomicInteger> ipTraffic) {
    StringBuilder stats = new StringBuilder();

    ipTraffic = ipTraffic.entrySet()
        .stream()
        .sorted((a, b) -> Integer.compare(b.getValue().get(), a.getValue().get()))
        .collect(
            Collectors
                .toMap(Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e1, LinkedHashMap::new));

    double total = ipTraffic.values().stream().mapToInt(AtomicInteger::get).sum();
    ipTraffic.forEach((k, v) -> stats
        .append(k.getHostAddress()) // IP
        .append(": ")
        .append(v.get()) // length by ip
        .append(" (")
        .append(v.get() / total) // percent
        .append("%)")
        .append("\n"));

    return stats.toString();
  }
}
