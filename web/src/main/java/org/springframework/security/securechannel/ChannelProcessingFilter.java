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

package org.springframework.security.securechannel;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.intercept.web.FilterInvocationSecurityMetadataSource;
import org.springframework.security.ui.FilterChainOrder;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.util.Assert;


/**
 * Ensures a web request is delivered over the required channel.
 * <p>Internally uses a {@link FilterInvocation} to represent the request, so that the
 * <code>FilterInvocation</code>-related property editors and lookup classes can be used.</p>
 * <p>Delegates the actual channel security decisions and necessary actions to the configured
 * {@link ChannelDecisionManager}. If a response is committed by the <code>ChannelDecisionManager</code>,
 * the filter chain will not proceed.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ChannelProcessingFilter extends SpringSecurityFilter implements InitializingBean {

    //~ Instance fields ================================================================================================

    private ChannelDecisionManager channelDecisionManager;
    private FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(filterInvocationSecurityMetadataSource, "filterInvocationSecurityMetadataSource must be specified");
        Assert.notNull(channelDecisionManager, "channelDecisionManager must be specified");

        Collection<ConfigAttribute> attrDefs = this.filterInvocationSecurityMetadataSource.getAllConfigAttributes();

        if (attrDefs == null) {
            if (logger.isWarnEnabled()) {
                logger.warn("Could not validate configuration attributes as the FilterInvocationSecurityMetadataSource did "
                        + "not return any attributes");
            }

            return;
        }

        Set<ConfigAttribute> unsupportedAttributes = new HashSet<ConfigAttribute>();

        for (ConfigAttribute attr : attrDefs) {
            if (!this.channelDecisionManager.supports(attr)) {
                unsupportedAttributes.add(attr);
            }
        }

        if (unsupportedAttributes.size() == 0) {
            if (logger.isInfoEnabled()) {
                logger.info("Validated configuration attributes");
            }
        } else {
            throw new IllegalArgumentException("Unsupported configuration attributes: " + unsupportedAttributes);
        }
    }

    public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        FilterInvocation fi = new FilterInvocation(request, response, chain);
        List<ConfigAttribute> attr = this.filterInvocationSecurityMetadataSource.getAttributes(fi);

        if (attr != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Request: " + fi.toString() + "; ConfigAttributes: " + attr);
            }

            channelDecisionManager.decide(fi, attr);

            if (fi.getResponse().isCommitted()) {
                return;
            }
        }

        chain.doFilter(request, response);
    }

    public ChannelDecisionManager getChannelDecisionManager() {
        return channelDecisionManager;
    }

    public FilterInvocationSecurityMetadataSource getFilterInvocationSecurityMetadataSource() {
        return filterInvocationSecurityMetadataSource;
    }

    public void setChannelDecisionManager(ChannelDecisionManager channelDecisionManager) {
        this.channelDecisionManager = channelDecisionManager;
    }

    public void setFilterInvocationSecurityMetadataSource(FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource) {
        this.filterInvocationSecurityMetadataSource = filterInvocationSecurityMetadataSource;
    }

    public int getOrder() {
        return FilterChainOrder.CHANNEL_FILTER;
    }
}
