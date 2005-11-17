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

import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.intercept.web.FilterInvocation;
import org.acegisecurity.intercept.web.FilterInvocationDefinitionSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import java.io.IOException;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Ensures a web request is delivered over the required channel.
 * 
 * <p>
 * Internally uses a {@link FilterInvocation} to represent the request, so that
 * the <code>FilterInvocation</code>-related property editors and lookup
 * classes can be used.
 * </p>
 * 
 * <P>
 * Delegates the actual channel security decisions and necessary actions to the
 * configured {@link ChannelDecisionManager}. If a response is committed by
 * the <code>ChannelDecisionManager</code>, the filter chain will not proceed.
 * </p>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead configure
 * <code>web.xml</code> to use the {@link
 * org.acegisecurity.util.FilterToBeanProxy}.
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
    private FilterInvocationDefinitionSource filterInvocationDefinitionSource;

    //~ Methods ================================================================

    public void setChannelDecisionManager(
        ChannelDecisionManager channelDecisionManager) {
        this.channelDecisionManager = channelDecisionManager;
    }

    public ChannelDecisionManager getChannelDecisionManager() {
        return channelDecisionManager;
    }

    public void setFilterInvocationDefinitionSource(
        FilterInvocationDefinitionSource filterInvocationDefinitionSource) {
        this.filterInvocationDefinitionSource = filterInvocationDefinitionSource;
    }

    public FilterInvocationDefinitionSource getFilterInvocationDefinitionSource() {
        return filterInvocationDefinitionSource;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(filterInvocationDefinitionSource, "filterInvocationDefinitionSource must be specified");
        Assert.notNull(channelDecisionManager, "channelDecisionManager must be specified");

        Iterator iter = this.filterInvocationDefinitionSource
                .getConfigAttributeDefinitions();

        if (iter == null) {
            if (logger.isWarnEnabled()) {
                logger.warn("Could not validate configuration attributes as the FilterInvocationDefinitionSource did not return a ConfigAttributeDefinition Iterator");
            }

            return;
        }

        Set set = new HashSet();

        while (iter.hasNext()) {
            ConfigAttributeDefinition def = (ConfigAttributeDefinition) iter
                    .next();
            Iterator attributes = def.getConfigAttributes();

            while (attributes.hasNext()) {
                ConfigAttribute attr = (ConfigAttribute) attributes.next();

                if (!this.channelDecisionManager.supports(attr)) {
                    set.add(attr);
                }
            }
        }

        if (set.size() == 0) {
            if (logger.isInfoEnabled()) {
                logger.info("Validated configuration attributes");
            }
        } else {
            throw new IllegalArgumentException("Unsupported configuration attributes: " + set.toString());
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
                logger.debug("Request: " + fi.getFullRequestUrl()
                    + "; ConfigAttributes: " + attr.toString());
            }

            channelDecisionManager.decide(fi, attr);

            if (fi.getResponse().isCommitted()) {
                return;
            }
        }

        chain.doFilter(request, response);
    }

    public void init(FilterConfig filterConfig) throws ServletException {}
}
