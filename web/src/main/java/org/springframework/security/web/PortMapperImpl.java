/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web;

import java.util.HashMap;
import java.util.Map;

import org.springframework.util.Assert;

/**
 * Concrete implementation of {@link PortMapper} that obtains HTTP:HTTPS pairs from the
 * application context.
 * <p>
 * By default the implementation will assume 80:443 and 8080:8443 are HTTP:HTTPS pairs
 * respectively. If different pairs are required, use {@link #setPortMappings(Map)}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class PortMapperImpl implements PortMapper {

	// ~ Instance fields
	// ================================================================================================

	private final Map<Integer, Integer> httpsPortMappings;

	// ~ Constructors
	// ===================================================================================================

	public PortMapperImpl() {
		this.httpsPortMappings = new HashMap<>();
		this.httpsPortMappings.put(80, 443);
		this.httpsPortMappings.put(8080, 8443);
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * Returns the translated (Integer -&gt; Integer) version of the original port mapping
	 * specified via setHttpsPortMapping()
	 */
	public Map<Integer, Integer> getTranslatedPortMappings() {
		return this.httpsPortMappings;
	}

	public Integer lookupHttpPort(Integer httpsPort) {
		for (Integer httpPort : this.httpsPortMappings.keySet()) {
			if (this.httpsPortMappings.get(httpPort).equals(httpsPort)) {
				return httpPort;
			}
		}

		return null;
	}

	public Integer lookupHttpsPort(Integer httpPort) {
		return this.httpsPortMappings.get(httpPort);
	}

	/**
	 * Set to override the default HTTP port to HTTPS port mappings of 80:443, and
	 * 8080:8443. In a Spring XML ApplicationContext, a definition would look something
	 * like this:
	 *
	 * <pre>
	 *  &lt;property name="portMappings"&gt;
	 *      &lt;map&gt;
	 *          &lt;entry key="80"&gt;&lt;value&gt;443&lt;/value&gt;&lt;/entry&gt;
	 *          &lt;entry key="8080"&gt;&lt;value&gt;8443&lt;/value&gt;&lt;/entry&gt;
	 *      &lt;/map&gt;
	 * &lt;/property&gt;
	 * </pre>
	 * @param newMappings A Map consisting of String keys and String values, where for
	 * each entry the key is the string representation of an integer HTTP port number, and
	 * the value is the string representation of the corresponding integer HTTPS port
	 * number.
	 * @throws IllegalArgumentException if input map does not consist of String keys and
	 * values, each representing an integer port number in the range 1-65535 for that
	 * mapping.
	 */
	public void setPortMappings(Map<String, String> newMappings) {
		Assert.notNull(newMappings, "A valid list of HTTPS port mappings must be provided");

		this.httpsPortMappings.clear();

		for (Map.Entry<String, String> entry : newMappings.entrySet()) {
			Integer httpPort = Integer.valueOf(entry.getKey());
			Integer httpsPort = Integer.valueOf(entry.getValue());

			if ((httpPort < 1) || (httpPort > 65535) || (httpsPort < 1) || (httpsPort > 65535)) {
				throw new IllegalArgumentException(
						"one or both ports out of legal range: " + httpPort + ", " + httpsPort);
			}

			this.httpsPortMappings.put(httpPort, httpsPort);
		}

		if (this.httpsPortMappings.size() < 1) {
			throw new IllegalArgumentException("must map at least one port");
		}
	}

}
