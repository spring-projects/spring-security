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

package net.sf.acegisecurity.securechannel;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.io.IOException;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Commences a secure channel by retrying the original request using HTTPS.
 * 
 * <P>
 * This entry point should suffice in most circumstances. However, it is not
 * intended to properly handle HTTP POSTs or other usage where a standard
 * redirect would cause an issue.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RetryWithHttpsEntryPoint implements InitializingBean,
    ChannelEntryPoint {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(RetryWithHttpsEntryPoint.class);

    //~ Instance fields ========================================================

    private Map httpsPortMappings;

    //~ Constructors ===========================================================

    public RetryWithHttpsEntryPoint() {
        httpsPortMappings = new HashMap();
        httpsPortMappings.put(new Integer(80), new Integer(443));
        httpsPortMappings.put(new Integer(8080), new Integer(8443));
    }

    //~ Methods ================================================================

    /**
     * <p>
     * Set to override the default http port to https port mappings of 80:443,
     * and  8080:8443.
     * </p>
     * In a Spring XML ApplicationContext, a definition would look something
     * like this:
     * <pre>
     *   &lt;property name="httpsPortMapping">
     *     &lt;map>
     *       &lt;entry key="80">&lt;value>443&lt;/value>&lt;/entry>
     *       &lt;entry key="8080">&lt;value>8443&lt;/value>&lt;/entry>
     *     &lt;/map>
     *   &lt;/property>
     * </pre>
     *
     * @param newMappings A Map consisting of String keys and String values,
     *        where for each entry the key is the string representation of an
     *        integer http port number, and the value is the string
     *        representation of the corresponding integer https port number.
     *
     * @throws IllegalArgumentException if input map does not consist of String
     *         keys and values, each representing an integer port number in
     *         the range 1-65535 for that mapping.
     */
    public void setHttpsPortMappings(HashMap newMappings) {
        httpsPortMappings.clear();

        Iterator it = newMappings.entrySet().iterator();

        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            Integer httpPort = new Integer((String) entry.getKey());
            Integer httpsPort = new Integer((String) entry.getValue());

            if ((httpPort.intValue() < 1) || (httpPort.intValue() > 65535)
                || (httpsPort.intValue() < 1) || (httpsPort.intValue() > 65535)) {
                throw new IllegalArgumentException(
                    "one or both ports out of legal range: " + httpPort + ", "
                    + httpsPort);
            }

            httpsPortMappings.put(httpPort, httpsPort);

            if (httpsPortMappings.size() < 1) {
                throw new IllegalArgumentException("must map at least one port");
            }
        }
    }

    public void afterPropertiesSet() throws Exception {
        if (httpsPortMappings == null) {
            throw new IllegalArgumentException("httpsPortMappings required");
        }
    }

    public void commence(ServletRequest request, ServletResponse response)
        throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        String pathInfo = req.getPathInfo();
        String queryString = req.getQueryString();
        String contextPath = req.getContextPath();
        String destination = req.getServletPath()
            + ((pathInfo == null) ? "" : pathInfo)
            + ((queryString == null) ? "" : ("?" + queryString));

        String redirectUrl = contextPath;

        Integer httpPort = new Integer(req.getServerPort());
        Integer httpsPort = (Integer) httpsPortMappings.get(httpPort);

        if (httpsPort != null) {
            String serverName = req.getServerName();
            redirectUrl = "https://" + serverName + ":" + httpsPort
                + contextPath + destination;
        }

        ((HttpServletResponse) response).sendRedirect(redirectUrl);
    }

    /**
     * Returns the translated (Integer -> Integer) version of the original port
     * mapping specified via setHttpsPortMapping()
     *
     * @return DOCUMENT ME!
     */
    protected Map getTranslatedHttpsPortMappings() {
        return httpsPortMappings;
    }
}
