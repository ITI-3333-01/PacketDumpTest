package com.austinlm.packetdump.util;

import com.austinlm.packetdump.Main;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class FileUtils {

  public static FileWriter createAndWrite(File outDir, String name) {
    try {
      File file = new File(outDir, name);
      return new FileWriter(file);
    } catch (IOException e) {
      Main.logger.severe("Failed to create output file: " + name);
      e.printStackTrace();
      System.exit(1);
    }

    return null;
  }

  /**
   * Construct a {@link File} using a file path.
   *
   * If the file already exists, the writter will be in append mode.
   *
   * If the file does not exist, it will be created and opened.
   *
   * @return writer for the specified path
   */
  public static File checkFile(String outPath) {
    if (outPath == null) {
      return null;
    }

    File file = new File(outPath);
    if (file.exists() && file.isDirectory()) {
      return file;
    } else {
      try {
        file.mkdirs();
        return file;
      } catch (SecurityException e) {
        Main.logger.severe("Failed to create output directory!");
        e.printStackTrace();
        System.exit(1);
      }
    }

    return null;
  }
}
