/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.util;

import org.springframework.beans.factory.InitializingBean;

import javax.servlet.ServletRequest;


/**
 * Concrete implementation of {@link PortResolver} that obtains the port from
 * <code>ServletRequest.getServerPort()</code>.
 * 
 * <P>
 * If either the <code>alwaysHttpPort</code> or <code>alwaysHttpsPort</code>
 * properties are set, these ports will be used <B>instead of</B> those
 * obtained from the <code>ServletRequest.getServerPort()</code> method.
 * Setting these properties will cause the
 * <code>ServletRequest.getScheme()</code> method to be used to determine
 * whether a request was HTTP or HTTPS, and then return the port defined by
 * the <code>always[Scheme]Port</code> property. You can configure zero, one
 * or both of these properties.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PortResolverImpl implements InitializingBean, PortResolver {
    //~ Instance fields ========================================================

    private int alwaysHttpPort = 0;
    private int alwaysHttpsPort = 0;

    //~ Methods ================================================================

    public void setAlwaysHttpPort(int alwaysHttpPort) {
        this.alwaysHttpPort = alwaysHttpPort;
    }

    public int getAlwaysHttpPort() {
        return alwaysHttpPort;
    }

    public void setAlwaysHttpsPort(int alwaysHttpsPort) {
        this.alwaysHttpsPort = alwaysHttpsPort;
    }

    public int getAlwaysHttpsPort() {
        return alwaysHttpsPort;
    }

    public int getServerPort(ServletRequest request) {
        if ("http".equals(request.getScheme().toLowerCase())
            && (alwaysHttpPort != 0)) {
            return alwaysHttpPort;
        }

        if ("https".equals(request.getScheme().toLowerCase())
            && (alwaysHttpsPort != 0)) {
            return alwaysHttpsPort;
        }

        return request.getServerPort();
    }

    public void afterPropertiesSet() throws Exception {
        if ((alwaysHttpPort != 0)
            && ((alwaysHttpPort > 65535) || (alwaysHttpPort < 0))) {
            throw new IllegalArgumentException(
                "alwaysHttpPort must be between 1 and 65535");
        }

        if ((alwaysHttpsPort != 0)
            && ((alwaysHttpsPort > 65535) || (alwaysHttpsPort < 0))) {
            throw new IllegalArgumentException(
                "alwaysHttpsPort must be between 1 and 65535");
        }
    }
}
