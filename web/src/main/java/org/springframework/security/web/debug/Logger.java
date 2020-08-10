/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.debug;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Controls output for the Spring Security debug feature.
 *
 * @author Luke Taylor
 * @since 3.1
 */
final class Logger {

	private static final Log logger = LogFactory.getLog("Spring Security Debugger");

	public void info(String message) {
		info(message, false);
	}

	public void info(String message, boolean dumpStack) {
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
