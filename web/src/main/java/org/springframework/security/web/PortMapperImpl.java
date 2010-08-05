/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web;

import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


/**
 * Concrete implementation of {@link PortMapper} that obtains HTTP:HTTPS pairs from the application context.
 * <p>
 * By default the implementation will assume 80:443 and 8080:8443 are HTTP:HTTPS pairs respectively. If different pairs
 * are required, use {@link #setPortMappings(Map)}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class PortMapperImpl implements PortMapper {
    //~ Instance fields ================================================================================================

    private final Map<Integer, Integer> httpsPortMappings;

    //~ Constructors ===================================================================================================

    public PortMapperImpl() {
        httpsPortMappings = new HashMap<Integer, Integer>();
        httpsPortMappings.put(new Integer(80), new Integer(443));
        httpsPortMappings.put(new Integer(8080), new Integer(8443));
    }

    //~ Methods ========================================================================================================

    /**
     * Returns the translated (Integer -> Integer) version of the original port mapping specified via
     * setHttpsPortMapping()
     */
    public Map<Integer, Integer> getTranslatedPortMappings() {
        return httpsPortMappings;
    }

    public Integer lookupHttpPort(Integer httpsPort) {
        for (Integer httpPort : httpsPortMappings.keySet()) {
            if (httpsPortMappings.get(httpPort).equals(httpsPort)) {
                return httpPort;
            }
        }

        return null;
    }

    public Integer lookupHttpsPort(Integer httpPort) {
        return httpsPortMappings.get(httpPort);
    }

    /**
     * Set to override the default HTTP port to HTTPS port mappings of 80:443, and  8080:8443.
     * In a Spring XML ApplicationContext, a definition would look something like this:
     * <pre>
     *  &lt;property name="portMappings">
     *      &lt;map>
     *          &lt;entry key="80">&lt;value>443&lt;/value>&lt;/entry>
     *          &lt;entry key="8080">&lt;value>8443&lt;/value>&lt;/entry>
     *      &lt;/map>
     * &lt;/property></pre>
     *
     * @param newMappings A Map consisting of String keys and String values, where for each entry the key is the string
     *        representation of an integer HTTP port number, and the value is the string representation of the
     *        corresponding integer HTTPS port number.
     *
     * @throws IllegalArgumentException if input map does not consist of String keys and values, each representing an
     *         integer port number in the range 1-65535 for that mapping.
     */
    public void setPortMappings(Map<String,String> newMappings) {
        Assert.notNull(newMappings, "A valid list of HTTPS port mappings must be provided");

        httpsPortMappings.clear();

        for (Map.Entry<String,String> entry : newMappings.entrySet()) {
            Integer httpPort = new Integer(entry.getKey());
            Integer httpsPort = new Integer(entry.getValue());

            if ((httpPort.intValue() < 1) || (httpPort.intValue() > 65535) || (httpsPort.intValue() < 1)
                || (httpsPort.intValue() > 65535)) {
                throw new IllegalArgumentException("one or both ports out of legal range: " + httpPort + ", "
                    + httpsPort);
            }

            httpsPortMappings.put(httpPort, httpsPort);
        }

        if (httpsPortMappings.size() < 1) {
            throw new IllegalArgumentException("must map at least one port");
        }
    }
}
