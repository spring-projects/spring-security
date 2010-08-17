package org.springframework.security.config.debug;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Controls output for the Spring Security debug feature.
 *
 * @author Luke Taylor
 * @since 3.1
 */
class Logger {
    final static Log logger = LogFactory.getLog("Spring Security Debugger");

    public static void log(String message) {
        log(message, false);
    }

    public static void log(String message, boolean dumpStack) {
        StringBuilder output = new StringBuilder(256);
        output.append("\n\n************************************************************\n\n");
        output.append(message).append("\n");

        if (dumpStack) {
            StringWriter os = new StringWriter();
            new Exception().printStackTrace(new PrintWriter(os));
            StringBuffer buffer = os.getBuffer();
            // Remove the exception in case it scares people.
            int start = buffer.indexOf("java.lang.Exception");
            buffer.replace(start, start + 19, "");
            output.append("\nCall stack: \n").append(os.toString());
        }

        output.append("\n\n************************************************************\n\n");

        logger.info(output.toString());
    }
}
