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
 * Used by the <code>SecurityEnforcementFilter</code> to commence
 * authentication via the {@link AuthenticationProcessingFilter}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class AuthenticationProcessingFilterEntryPoint
    implements AuthenticationEntryPoint, InitializingBean {
    //~ Instance fields ========================================================

    /**
     * The URL where the <code>AuthenticationProcessingFilter</code> login page
     * can be found.
     */
    private String loginFormUrl;
    
    private boolean forceHttps = false;
    
    private HashMap httpsPortMapping;

    //~ Methods ================================================================
    
    public AuthenticationProcessingFilterEntryPoint() {
        httpsPortMapping = new HashMap();
        httpsPortMapping.put(new Integer(80), new Integer(443));
        httpsPortMapping.put(new Integer(8080), new Integer(8443));
    }

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
        
        String redirectUrl =  contextPath + loginFormUrl;
        
        if (forceHttps && req.getScheme().equals("http")) {
            Integer httpPort = new Integer(req.getServerPort());
            Integer httpsPort = (Integer) httpsPortMapping.get(httpPort);
            if (httpsPort != null ) {
                String serverName = req.getServerName();
                redirectUrl = "https://" + serverName + ":" + httpsPort + contextPath
                        + loginFormUrl;
            }
        }
        
        ((HttpServletResponse) response).sendRedirect(redirectUrl);
    }
    
    public void setForceHttps(boolean forceSsl) {
        this.forceHttps = forceSsl;
    }
    public boolean getForceHttps() {
        return forceHttps;
    }

    /**
     * @throws IllegalArgumentException if input map does not consist of String keys
     * and values, each representing an integer port number for one mapping.
     */
    public void setHttpsPortMapping(HashMap newMappings) {
        httpsPortMapping.clear();
        Iterator it = newMappings.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            Integer httpPort = new Integer((String)entry.getKey());
            Integer httpsPort = new Integer((String)entry.getValue());
            if (httpPort.intValue() < 1 || httpPort.intValue() > 65535 ||
                    httpsPort.intValue() < 1 || httpsPort.intValue() > 65535)
                throw new IllegalArgumentException("one or both ports out of legal range: "
                        + httpPort + ", " + httpsPort);
            httpsPortMapping.put(httpPort, httpsPort);
            if (httpsPortMapping.size() < 1)
                throw new IllegalArgumentException("must map at least one port");
        }
        
    }
    
    /**
     * Returns the translated (Integer -> Integer) version of the original port
     * mapping specified via setHttpsPortMapping() 
     */
    protected HashMap getTranslatedHttpsPortMapping() {
        return httpsPortMapping;
    }
}
