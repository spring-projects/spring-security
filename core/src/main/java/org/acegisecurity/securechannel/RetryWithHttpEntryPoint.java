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

package org.acegisecurity.securechannel;

import org.acegisecurity.util.PortMapper;
import org.acegisecurity.util.PortMapperImpl;
import org.acegisecurity.util.PortResolver;
import org.acegisecurity.util.PortResolverImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Commences an insecure channel by retrying the original request using HTTP.
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
public class RetryWithHttpEntryPoint implements InitializingBean,
    ChannelEntryPoint {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(RetryWithHttpEntryPoint.class);

    //~ Instance fields ========================================================

    private PortMapper portMapper = new PortMapperImpl();
    private PortResolver portResolver = new PortResolverImpl();

    //~ Methods ================================================================

    public void setPortMapper(PortMapper portMapper) {
        this.portMapper = portMapper;
    }

    public PortMapper getPortMapper() {
        return portMapper;
    }

    public void setPortResolver(PortResolver portResolver) {
        this.portResolver = portResolver;
    }

    public PortResolver getPortResolver() {
        return portResolver;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(portMapper, "portMapper is required");
        Assert.notNull(portResolver, "portResolver is required");
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

        Integer httpsPort = new Integer(portResolver.getServerPort(req));
        Integer httpPort = portMapper.lookupHttpPort(httpsPort);

        if (httpPort != null) {
            boolean includePort = true;

            if (httpPort.intValue() == 80) {
                includePort = false;
            }

            redirectUrl = "http://" + req.getServerName()
                + ((includePort) ? (":" + httpPort) : "") + contextPath
                + destination;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Redirecting to: " + redirectUrl);
        }

        ((HttpServletResponse) response).sendRedirect(((HttpServletResponse) response)
            .encodeRedirectURL(redirectUrl));
    }
}
