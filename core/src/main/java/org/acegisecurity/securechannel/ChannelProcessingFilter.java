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

import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.intercept.web.FilterInvocation;
import net.sf.acegisecurity.intercept.web.FilterInvocationDefinitionSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Ensures a request is delivered over a secure channel.
 * 
 * <p>
 * Internally uses a {@link FilterInvocation} to represent the request, so that
 * the <code>FilterInvocation</code>-related property editors and lookup
 * classes can be used.
 * </p>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead configure
 * <code>web.xml</code> to use the {@link
 * net.sf.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ChannelProcessingFilter implements InitializingBean, Filter {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(ChannelProcessingFilter.class);

    //~ Instance fields ========================================================

    private ChannelDecisionManager channelDecisionManager;
    private ChannelEntryPoint channelEntryPoint;
    private FilterInvocationDefinitionSource filterInvocationDefinitionSource;

    //~ Methods ================================================================

    public void setChannelDecisionManager(
        ChannelDecisionManager channelDecisionManager) {
        this.channelDecisionManager = channelDecisionManager;
    }

    public ChannelDecisionManager getChannelDecisionManager() {
        return channelDecisionManager;
    }

    public void setChannelEntryPoint(ChannelEntryPoint channelEntryPoint) {
        this.channelEntryPoint = channelEntryPoint;
    }

    public ChannelEntryPoint getChannelEntryPoint() {
        return channelEntryPoint;
    }

    public void setFilterInvocationDefinitionSource(
        FilterInvocationDefinitionSource filterInvocationDefinitionSource) {
        this.filterInvocationDefinitionSource = filterInvocationDefinitionSource;
    }

    public FilterInvocationDefinitionSource getFilterInvocationDefinitionSource() {
        return filterInvocationDefinitionSource;
    }

    public void afterPropertiesSet() throws Exception {
        if (filterInvocationDefinitionSource == null) {
            throw new IllegalArgumentException(
                "filterInvocationDefinitionSource must be specified");
        }

        if (channelDecisionManager == null) {
            throw new IllegalArgumentException(
                "channelDecisionManager must be specified");
        }

        if (channelEntryPoint == null) {
            throw new IllegalArgumentException(
                "channelEntryPoint must be specified");
        }
    }

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("HttpServletRequest required");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("HttpServletResponse required");
        }

        FilterInvocation fi = new FilterInvocation(request, response, chain);
        ConfigAttributeDefinition attr = this.filterInvocationDefinitionSource
            .getAttributes(fi);

        if (attr != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Request : " + request.toString()
                    + "; ConfigAttributes: " + attr.toString());
            }

            try {
                channelDecisionManager.decide(fi, attr);
            } catch (SecureChannelRequiredException channelException) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Channel insufficient ("
                        + channelException.getMessage()
                        + "); delegating to channelEntryPoint");
                }

                channelEntryPoint.commence(request, response);
            }
        }

        chain.doFilter(request, response);
    }

    public void init(FilterConfig filterConfig) throws ServletException {}
}
