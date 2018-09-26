package com.austinlm.packetdump.util;

import java.util.logging.ConsoleHandler;
import java.util.logging.Logger;

/**
 * Logging utils
 *
 * @author austinlm
 */
public class Logging {

  /**
   * Get a new logger by name, bind it to console, and format it with our {@link CustomFormatter} so
   * everything looks nice.
   *
   * @param name of the logger to created
   * @return a new logger all setup
   */
  public static Logger getLogger(String name) {
    ConsoleHandler handler = new ConsoleHandler();
    handler.setFormatter(new CustomFormatter());
    Logger logger = Logger.getLogger(name);
    logger.addHandler(handler);
    logger.setUseParentHandlers(false);
    return logger;
  }
}
