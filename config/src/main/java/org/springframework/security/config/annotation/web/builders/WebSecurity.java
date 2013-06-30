/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * <p>
 * The {@link WebSecurity} is created by {@link WebSecurityConfiguration}
 * to create the {@link FilterChainProxy} known as the Spring Security Filter
 * Chain (springSecurityFilterChain). The springSecurityFilterChain is the
 * {@link Filter} that the {@link DelegatingFilterProxy} delegates to.
 * </p>
 *
 * <p>
 * Customizations to the {@link WebSecurity} can be made by creating a
 * {@link WebSecurityConfigurer} or more likely by overriding
 * {@link WebSecurityConfigurerAdapter}.
 * </p>
 *
 * @see EnableWebSecurity
 * @see WebSecurityConfiguration
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class WebSecurity extends
        AbstractConfiguredSecurityBuilder<Filter, WebSecurity> implements SecurityBuilder<Filter> {
    private final Log logger = LogFactory.getLog(getClass());

    private final List<RequestMatcher> ignoredRequests = new ArrayList<RequestMatcher>();

    private final List<SecurityBuilder<? extends SecurityFilterChain>> securityFilterChainBuilders =
            new ArrayList<SecurityBuilder<? extends SecurityFilterChain>>();

    private final IgnoredRequestConfigurer ignoredRequestRegistry =
            new IgnoredRequestConfigurer();

    private FilterSecurityInterceptor filterSecurityInterceptor;

    private HttpFirewall httpFirewall;

    private boolean debugEnabled;

    private WebInvocationPrivilegeEvaluator privilegeEvaluator;

    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

    /**
     * Creates a new instance
     * @see WebSecurityConfiguration
     */
    public WebSecurity() {
    }

    /**
     * <p>
     * Allows adding {@link RequestMatcher} instances that should that Spring
     * Security should ignore. Web Security provided by Spring Security
     * (including the {@link SecurityContext}) will not be available on
     * {@link HttpServletRequest} that match. Typically the requests that are
     * registered should be that of only static resources. For requests that are
     * dynamic, consider mapping the request to allow all users instead.
     * </p>
     *
     * Example Usage:
     *
     * <pre>
     * webSecurityBuilder
     *     .ignoring()
     *         // ignore all URLs that start with /resources/ or /static/
     *         .antMatchers(&quot;/resources/**&quot;, &quot;/static/**&quot;);
     * </pre>
     *
     * Alternatively this will accomplish the same result:
     *
     * <pre>
     * webSecurityBuilder
     *     .ignoring()
     *         // ignore all URLs that start with /resources/ or /static/
     *         .antMatchers(&quot;/resources/**&quot;)
     *         .antMatchers(&quot;/static/**&quot;);
     * </pre>
     *
     * Multiple invocations of ignoring() are also additive, so the following is
     * also equivalent to the previous two examples:
     *
     * Alternatively this will accomplish the same result:
     *
     * <pre>
     * webSecurityBuilder
     *     .ignoring()
     *         // ignore all URLs that start with /resources/
     *         .antMatchers(&quot;/resources/**&quot;);
     * webSecurityBuilder
     *     .ignoring()
     *         // ignore all URLs that start with /static/
     *         .antMatchers(&quot;/static/**&quot;);
     * // now both URLs that start with /resources/ and /static/ will be ignored
     * </pre>
     *
     * @return the {@link IgnoredRequestConfigurer} to use for registering request
     *         that should be ignored
     */
    public IgnoredRequestConfigurer ignoring() {
        return ignoredRequestRegistry;
    }

    /**
     * Allows customizing the {@link HttpFirewall}. The default is
     * {@link DefaultHttpFirewall}.
     *
     * @param httpFirewall the custom {@link HttpFirewall}
     * @return the {@link WebSecurity} for further customizations
     */
    public WebSecurity httpFirewall(HttpFirewall httpFirewall) {
        this.httpFirewall = httpFirewall;
        return this;
    }

    /**
     * Controls debugging support for Spring Security.
     *
     * @param debugEnabled
     *            if true, enables debug support with Spring Security. Default
     *            is false.
     *
     * @return the {@link WebSecurity} for further customization.
     * @see EnableWebSecurity#debug()
     */
    public WebSecurity debug(boolean debugEnabled) {
        this.debugEnabled = debugEnabled;
        return this;
    }

    /**
     * <p>
     * Adds builders to create {@link SecurityFilterChain} instances.
     * </p>
     *
     * <p>
     * Typically this method is invoked automatically within the framework from
     * {@link WebSecurityConfigurerAdapter#init(WebSecurity)}
     * </p>
     *
     * @param securityFilterChainBuilder
     *            the builder to use to create the {@link SecurityFilterChain}
     *            instances
     * @return the {@link WebSecurity} for further customizations
     */
    public WebSecurity addSecurityFilterChainBuilder(SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder) {
        this.securityFilterChainBuilders.add(securityFilterChainBuilder);
        return this;
    }

    /**
     * Set the {@link WebInvocationPrivilegeEvaluator} to be used. If this is
     * null, then a {@link DefaultWebInvocationPrivilegeEvaluator} will be
     * created when {@link #setSecurityInterceptor(FilterSecurityInterceptor)}
     * is non null.
     *
     * @param privilegeEvaluator
     *            the {@link WebInvocationPrivilegeEvaluator} to use
     * @return the {@link WebSecurity} for further customizations
     */
    public WebSecurity privilegeEvaluator(WebInvocationPrivilegeEvaluator privilegeEvaluator) {
        this.privilegeEvaluator = privilegeEvaluator;
        return this;
    }

    /**
     * Set the {@link SecurityExpressionHandler} to be used. If this is null,
     * then a {@link DefaultWebSecurityExpressionHandler} will be used.
     *
     * @param expressionHandler
     *            the {@link SecurityExpressionHandler} to use
     * @return the {@link WebSecurity} for further customizations
     */
    public WebSecurity expressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
        Assert.notNull(expressionHandler, "expressionHandler cannot be null");
        this.expressionHandler = expressionHandler;
        return this;
    }

    /**
     * Gets the {@link SecurityExpressionHandler} to be used.
     * @return
     */
    public SecurityExpressionHandler<FilterInvocation> getExpressionHandler() {
        return expressionHandler;
    }

    /**
     * Gets the {@link WebInvocationPrivilegeEvaluator} to be used.
     * @return
     */
    public WebInvocationPrivilegeEvaluator getPrivilegeEvaluator() {
        if(privilegeEvaluator != null) {
            return privilegeEvaluator;
        }
        return filterSecurityInterceptor == null ? null : new DefaultWebInvocationPrivilegeEvaluator(filterSecurityInterceptor);
    }

    /**
     * Sets the {@link FilterSecurityInterceptor}. This is typically invoked by {@link WebSecurityConfigurerAdapter}.
     * @param securityInterceptor the {@link FilterSecurityInterceptor} to use
     */
    public void setSecurityInterceptor(FilterSecurityInterceptor securityInterceptor) {
        this.filterSecurityInterceptor = securityInterceptor;
    }

    @Override
    protected Filter performBuild() throws Exception {
        Assert.state(!securityFilterChainBuilders.isEmpty(), "At least one SecurityFilterBuilder needs to be specified. Invoke FilterChainProxyBuilder.securityFilterChains");
        int chainSize = ignoredRequests.size() + securityFilterChainBuilders.size();
        List<SecurityFilterChain> securityFilterChains = new ArrayList<SecurityFilterChain>(chainSize);
        for(RequestMatcher ignoredRequest : ignoredRequests) {
            securityFilterChains.add(new DefaultSecurityFilterChain(ignoredRequest));
        }
        for(SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder : securityFilterChainBuilders) {
            securityFilterChains.add(securityFilterChainBuilder.build());
        }
        FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
        if(httpFirewall != null) {
            filterChainProxy.setFirewall(httpFirewall);
        }
        filterChainProxy.afterPropertiesSet();

        Filter result = filterChainProxy;
        if(debugEnabled) {
            logger.warn("\n\n" +
                    "********************************************************************\n" +
                    "**********        Security debugging is enabled.       *************\n" +
                    "**********    This may include sensitive information.  *************\n" +
                    "**********      Do not use in a production system!     *************\n" +
                    "********************************************************************\n\n");
            result = new DebugFilter(filterChainProxy);
        }
        return result;
    }

    /**
     * Allows registering {@link RequestMatcher} instances that should be
     * ignored by Spring Security.
     *
     * @author Rob Winch
     * @since 3.2
     */
    public final class IgnoredRequestConfigurer extends AbstractRequestMatcherConfigurer<WebSecurity,IgnoredRequestConfigurer,Filter> {

        @Override
        protected IgnoredRequestConfigurer chainRequestMatchers(List<RequestMatcher> requestMatchers) {
            ignoredRequests.addAll(requestMatchers);
            return this;
        }

        /**
         * Returns the {@link WebSecurity} to be returned for chaining.
         */
        @Override
        public WebSecurity and() {
            return WebSecurity.this;
        }

        private IgnoredRequestConfigurer(){}
    }
}
