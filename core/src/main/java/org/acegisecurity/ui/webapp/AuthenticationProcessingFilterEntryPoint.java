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

package net.sf.acegisecurity.ui.webapp;

import net.sf.acegisecurity.intercept.web.AuthenticationEntryPoint;

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
 * <p>
 * Used by the <code>SecurityEnforcementFilter</code> to commence
 * authentication via the {@link AuthenticationProcessingFilter}. This object
 * holds the location of the login form, relative to the web app context path,
 * and is used to commence a redirect to that form.
 * </p>
 * 
 * <p>
 * By setting the <em>forceHttps</em> property to true, you may configure the
 * class to force the protocol used for the login form to be
 * <code>https</code>, even if the original intercepted request for a resource
 * used the <code>http</code> protocol. When this happens, after a successful
 * login (via https), the original resource will still be accessed as http,
 * via the original request URL. For the forced https feature to work, the
 * class must have a valid mapping from an http port in the original request
 * to an https port for the login page (the same server name will be used,
 * only the scheme and port will be changed). By default, http requests to
 * port 80 will be mapped to login page https requests on port 443 (standard
 * https port), and port 8080 will be mapped to port 8443. These mappings may
 * be customized by setting the <em>httpsPortMappings</em> property. Any
 * intercepted http request on a port which does not have a mapping will
 * result in the protocol remaining as http. Any intercepted request which is
 * already https will always result in the login page being accessed as https,
 * regardless of the state of the  <em>forceHttps</em> property.
 * </p>
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class AuthenticationProcessingFilterEntryPoint
    implements AuthenticationEntryPoint, InitializingBean {
    //~ Instance fields ========================================================

    private HashMap httpsPortMappings;
    private String loginFormUrl;
    private boolean forceHttps = false;

    //~ Constructors ===========================================================

    public AuthenticationProcessingFilterEntryPoint() {
        httpsPortMappings = new HashMap();
        httpsPortMappings.put(new Integer(80), new Integer(443));
        httpsPortMappings.put(new Integer(8080), new Integer(8443));
    }

    //~ Methods ================================================================

    /**
     * Set to true to force login form access to be via https. If this value is
     * ture (the default is false), and the incoming request for the protected
     * resource which triggered the interceptor was not already
     * <code>https</code>, then
     *
     * @param forceHttps
     *
     * @todo Generated comment
     */
    public void setForceHttps(boolean forceHttps) {
        this.forceHttps = forceHttps;
    }

    public boolean getForceHttps() {
        return forceHttps;
    }

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

    /**
     * The URL where the <code>AuthenticationProcessingFilter</code> login page
     * can be found. Should be relative to the web-app context path, and
     * include a leading <code>/</code>
     *
     * @param loginFormUrl
     */
    public void setLoginFormUrl(String loginFormUrl) {
        this.loginFormUrl = loginFormUrl;
    }

    public String getLoginFormUrl() {
        return loginFormUrl;
    }

    public void afterPropertiesSet() throws Exception {
        if ((loginFormUrl == null) || "".equals(loginFormUrl)) {
            throw new IllegalArgumentException("loginFormUrl must be specified");
        }
    }

    public void commence(ServletRequest request, ServletResponse response)
        throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String contextPath = req.getContextPath();

        String redirectUrl = contextPath + loginFormUrl;

        if (forceHttps && req.getScheme().equals("http")) {
            Integer httpPort = new Integer(req.getServerPort());
            Integer httpsPort = (Integer) httpsPortMappings.get(httpPort);

            if (httpsPort != null) {
                String serverName = req.getServerName();
                redirectUrl = "https://" + serverName + ":" + httpsPort
                    + contextPath + loginFormUrl;
            }
        }

        ((HttpServletResponse) response).sendRedirect(redirectUrl);
    }

    /**
     * Returns the translated (Integer -> Integer) version of the original port
     * mapping specified via setHttpsPortMapping()
     *
     * @return DOCUMENT ME!
     */
    protected HashMap getTranslatedHttpsPortMappings() {
        return httpsPortMappings;
    }
}
