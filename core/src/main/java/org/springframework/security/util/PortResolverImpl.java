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

package org.springframework.security.util;

import org.springframework.util.Assert;

import javax.servlet.ServletRequest;


/**
 * Concrete implementation of {@link PortResolver} that obtains the port from <tt>ServletRequest.getServerPort()</tt>.
 * <p>
 * This class is capable of handling the IE bug which results in an
 * incorrect URL being presented in the header subsequent to a redirect to a different scheme and port where the port
 * is not a well-known number (ie 80 or 443). Handling involves detecting an incorrect response from
 * <code>ServletRequest.getServerPort()</code> for the scheme (eg a HTTP request on 8443) and then determining the
 * real server port (eg HTTP request is really on 8080). The map of valid ports is obtained from the configured
 * {@link PortMapper}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PortResolverImpl implements PortResolver {
    //~ Instance fields ================================================================================================

    private PortMapper portMapper = new PortMapperImpl();

    //~ Methods ========================================================================================================

    public PortMapper getPortMapper() {
        return portMapper;
    }

    public int getServerPort(ServletRequest request) {
        int serverPort = request.getServerPort();
        Integer portLookup = null;

        String scheme = request.getScheme().toLowerCase();

        if ("http".equals(scheme)) {
            portLookup = portMapper.lookupHttpPort(new Integer(serverPort));

        } else if ("https".equals(scheme)) {
            portLookup = portMapper.lookupHttpsPort(new Integer(serverPort));
        }

        if (portLookup != null) {
            // IE 6 bug
            serverPort = portLookup.intValue();
        }

        return serverPort;
    }

    public void setPortMapper(PortMapper portMapper) {
        Assert.notNull(portMapper, "portMapper cannot be null");
        this.portMapper = portMapper;
    }
}
