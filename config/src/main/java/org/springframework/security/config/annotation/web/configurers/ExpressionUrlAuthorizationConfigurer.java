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
package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Adds URL based authorization based upon SpEL expressions to an application. At least one
 * {@link org.springframework.web.bind.annotation.RequestMapping} needs to be mapped to {@link ConfigAttribute}'s for
 * this {@link SecurityContextConfigurer} to have meaning.
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 *     <li>{@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated to allow other {@link org.springframework.security.config.annotation.SecurityConfigurer}'s to customize:
 * <ul>
 *     <li>{@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * <ul>
 * <li>{@link AuthenticationTrustResolver} is optionally used to populate the {@link DefaultWebSecurityExpressionHandler}</li>
 * </ul>
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 *
 * @author Rob Winch
 * @since 3.2
 * @see {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#authorizeRequests()}
 */
public final class ExpressionUrlAuthorizationConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractInterceptUrlConfigurer<H,ExpressionUrlAuthorizationConfigurer<H>,ExpressionUrlAuthorizationConfigurer<H>.AuthorizedUrl> {
    static final String permitAll = "permitAll";
    private static final String denyAll = "denyAll";
    private static final String anonymous = "anonymous";
    private static final String authenticated = "authenticated";
    private static final String fullyAuthenticated = "fullyAuthenticated";
    private static final String rememberMe = "rememberMe";

    private SecurityExpressionHandler<FilterInvocation> expressionHandler;

    /**
     * Creates a new instance
     * @see HttpSecurity#authorizeRequests()
     */
    public ExpressionUrlAuthorizationConfigurer() {
    }

    /**
     * Allows customization of the {@link SecurityExpressionHandler} to be used. The default is {@link DefaultWebSecurityExpressionHandler}
     *
     * @param expressionHandler the {@link SecurityExpressionHandler} to be used
     * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization.
     */
    public ExpressionUrlAuthorizationConfigurer<H> expressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
        this.expressionHandler = expressionHandler;
        return this;
    }

    /**
     * Adds an {@link ObjectPostProcessor} for this class.
     *
     * @param objectPostProcessor
     * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
     */
    public ExpressionUrlAuthorizationConfigurer<H> withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
        addObjectPostProcessor(objectPostProcessor);
        return this;
    }

    @Override
    protected final AuthorizedUrl chainRequestMatchersInternal(List<RequestMatcher> requestMatchers) {
        return new AuthorizedUrl(requestMatchers);
    }

    @Override
    @SuppressWarnings("rawtypes")
    final List<AccessDecisionVoter> getDecisionVoters(H http) {
        List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
        WebExpressionVoter expressionVoter = new WebExpressionVoter();
        expressionVoter.setExpressionHandler(getExpressionHandler(http));
        decisionVoters.add(expressionVoter);
        return decisionVoters;
    }

    @Override
    final ExpressionBasedFilterInvocationSecurityMetadataSource createMetadataSource(H http) {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = createRequestMap();
        if(requestMap.isEmpty()) {
            throw new IllegalStateException("At least one mapping is required (i.e. authorizeRequests().anyRequest.authenticated())");
        }
        return new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, getExpressionHandler(http));
    }

    /**
     * Allows registering multiple {@link RequestMatcher} instances to a collection of {@link ConfigAttribute} instances
     *
     * @param requestMatchers the {@link RequestMatcher} instances to register to the {@link ConfigAttribute} instances
     * @param configAttributes the {@link ConfigAttribute} to be mapped by the {@link RequestMatcher} instances
     * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization.
     */
    private ExpressionUrlAuthorizationConfigurer<H> interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, Collection<ConfigAttribute> configAttributes) {
        for(RequestMatcher requestMatcher : requestMatchers) {
            addMapping(new UrlMapping(requestMatcher, configAttributes));
        }
        return this;
    }

    private SecurityExpressionHandler<FilterInvocation> getExpressionHandler(H http) {
        if(expressionHandler == null) {
            DefaultWebSecurityExpressionHandler defaultHandler = new DefaultWebSecurityExpressionHandler();
            AuthenticationTrustResolver trustResolver = http.getSharedObject(AuthenticationTrustResolver.class);
            if(trustResolver != null) {
                defaultHandler.setTrustResolver(trustResolver);
            }
            expressionHandler = defaultHandler;
        }

        return expressionHandler;
    }

    private static String hasRole(String role) {
        Assert.notNull(role, "role cannot be null");
        if (role.startsWith("ROLE_")) {
            throw new IllegalArgumentException("role should not start with 'ROLE_' since it is automatically inserted. Got '" + role + "'");
        }
        return "hasRole('ROLE_" + role + "')";
    }

    private static String hasAuthority(String authority) {
        return "hasAuthority('" + authority + "')";
    }

    private static String hasAnyAuthority(String... authorities) {
        String anyAuthorities = StringUtils.arrayToDelimitedString(authorities, "','");
        return "hasAnyAuthority('" + anyAuthorities + "')";
    }

    private static String hasIpAddress(String ipAddressExpression) {
        return "hasIpAddress('" + ipAddressExpression + "')";
    }

    public final class AuthorizedUrl {
        private List<RequestMatcher> requestMatchers;
        private boolean not;

        /**
         * Creates a new instance
         *
         * @param requestMatchers the {@link RequestMatcher} instances to map
         */
        private AuthorizedUrl(List<RequestMatcher> requestMatchers) {
            this.requestMatchers = requestMatchers;
        }

        /**
         * Negates the following expression.
         *
         * @param role the role to require (i.e. USER, ADMIN, etc). Note, it should not start with "ROLE_" as
         *             this is automatically inserted.
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public AuthorizedUrl not() {
            this.not = true;
            return this;
        }

        /**
         * Shortcut for specifying URLs require a particular role. If you do not want to have "ROLE_" automatically
         * inserted see {@link #hasAuthority(String)}.
         *
         * @param role the role to require (i.e. USER, ADMIN, etc). Note, it should not start with "ROLE_" as
         *             this is automatically inserted.
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> hasRole(String role) {
            return access(ExpressionUrlAuthorizationConfigurer.hasRole(role));
        }

        /**
         * Specify that URLs require a particular authority.
         *
         * @param authority the authority to require (i.e. ROLE_USER, ROLE_ADMIN, etc).
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> hasAuthority(String authority) {
            return access(ExpressionUrlAuthorizationConfigurer.hasAuthority(authority));
        }

        /**
         * Specify that URLs requires any of a number authorities.
         *
         * @param authorities the requests require at least one of the authorities (i.e. "ROLE_USER","ROLE_ADMIN" would
         *                    mean either "ROLE_USER" or "ROLE_ADMIN" is required).
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> hasAnyAuthority(String... authorities) {
            return access(ExpressionUrlAuthorizationConfigurer.hasAnyAuthority(authorities));
        }

        /**
         * Specify that URLs requires a specific IP Address or
         * <a href="http://forum.springsource.org/showthread.php?102783-How-to-use-hasIpAddress&p=343971#post343971">subnet</a>.
         *
         * @param ipaddressExpression the ipaddress (i.e. 192.168.1.79) or local subnet (i.e. 192.168.0/24)
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> hasIpAddress(String ipaddressExpression) {
            return access(ExpressionUrlAuthorizationConfigurer.hasIpAddress(ipaddressExpression));
        }

        /**
         * Specify that URLs are allowed by anyone.
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> permitAll() {
            return access(permitAll);
        }

        /**
         * Specify that URLs are allowed by anonymous users.
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> anonymous() {
            return access(anonymous);
        }

        /**
         * Specify that URLs are allowed by users that have been remembered.
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * @see {@link RememberMeConfigurer}
         */
        public ExpressionUrlAuthorizationConfigurer<H> rememberMe() {
            return access(rememberMe);
        }

        /**
         * Specify that URLs are not allowed by anyone.
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> denyAll() {
            return access(denyAll);
        }

        /**
         * Specify that URLs are allowed by any authenticated user.
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> authenticated() {
            return access(authenticated);
        }

        /**
         * Specify that URLs are allowed by users who have authenticated and were not "remembered".
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * @see {@link RememberMeConfigurer}
         */
        public ExpressionUrlAuthorizationConfigurer<H> fullyAuthenticated() {
            return access(fullyAuthenticated);
        }

        /**
         * Allows specifying that URLs are secured by an arbitrary expression
         *
         * @param attribute the expression to secure the URLs (i.e. "hasRole('ROLE_USER') and hasRole('ROLE_SUPER')")
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         */
        public ExpressionUrlAuthorizationConfigurer<H> access(String attribute) {
            if(not) {
                attribute = "!" + attribute;
            }
            interceptUrl(requestMatchers, SecurityConfig.createList(attribute));
            return ExpressionUrlAuthorizationConfigurer.this;
        }
    }
}