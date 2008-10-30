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
import org.springframework.security.intercept.web.FilterInvocationDefinitionSource;
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
    private FilterInvocationDefinitionSource filterInvocationDefinitionSource;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(filterInvocationDefinitionSource, "filterInvocationDefinitionSource must be specified");
        Assert.notNull(channelDecisionManager, "channelDecisionManager must be specified");

        Collection<List<? extends ConfigAttribute>> attrDefs = this.filterInvocationDefinitionSource.getAllConfigAttributes();

        if (attrDefs == null) {
            if (logger.isWarnEnabled()) {
                logger.warn("Could not validate configuration attributes as the FilterInvocationDefinitionSource did "
                        + "not return any attributes");
            }

            return;
        }

        Set set = new HashSet();

        for (List<? extends ConfigAttribute> def : attrDefs) {
            for (ConfigAttribute attr : def) {
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

    public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        FilterInvocation fi = new FilterInvocation(request, response, chain);
        List<ConfigAttribute> attr = this.filterInvocationDefinitionSource.getAttributes(fi);

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

    public FilterInvocationDefinitionSource getFilterInvocationDefinitionSource() {
        return filterInvocationDefinitionSource;
    }

    public void setChannelDecisionManager(ChannelDecisionManager channelDecisionManager) {
        this.channelDecisionManager = channelDecisionManager;
    }

    public void setFilterInvocationDefinitionSource(FilterInvocationDefinitionSource filterInvocationDefinitionSource) {
        this.filterInvocationDefinitionSource = filterInvocationDefinitionSource;
    }

    public int getOrder() {
        return FilterChainOrder.CHANNEL_FILTER;
    }
}
