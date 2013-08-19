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

import java.util.List;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * A base class for configuring the {@link FilterSecurityInterceptor}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 *     <li>{@link FilterSecurityInterceptor}</li>
 * </ul>
  *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated to allow other {@link SecurityConfigurer}'s to customize:
 * <ul>
 *     <li>{@link FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 *     <li>{@link org.springframework.security.config.annotation.web.builders.HttpSecurity#getAuthenticationManager()}</li>
 * </ul>
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 * @param <C> the type of object that is changed
 * @param <R> the type of object that is changed for the {@link AbstractRequestMatcherMappingConfigurer}
 *
 * @author Rob Winch
 * @since 3.2
 * @see ExpressionUrlAuthorizationConfigurer
 * @see UrlAuthorizationConfigurer
 */
abstract class AbstractInterceptUrlConfigurer<H extends HttpSecurityBuilder<H>,C,R> extends
        AbstractRequestMatcherMappingConfigurer<H,R,DefaultSecurityFilterChain> implements
        SecurityConfigurer<DefaultSecurityFilterChain,H> {
    private Boolean filterSecurityInterceptorOncePerRequest;

    private AccessDecisionManager accessDecisionManager;

    /**
     * Allows setting the {@link AccessDecisionManager}. If none is provided, a default {@l AccessDecisionManager} is
     * created.
     *
     * @param accessDecisionManager the {@link AccessDecisionManager} to use
     * @return  the {@link AbstractInterceptUrlConfigurer} for further customization
     */
    public C accessDecisionManager(
            AccessDecisionManager accessDecisionManager) {
        this.accessDecisionManager = accessDecisionManager;
        return getSelf();
    }

    /**
     * Allows setting if the {@link FilterSecurityInterceptor} should be only applied once per request (i.e. if the
     * filter intercepts on a forward, should it be applied again).
     *
     * @param filterSecurityInterceptorOncePerRequest if the {@link FilterSecurityInterceptor} should be only applied
     *                                                once per request
     * @return  the {@link AbstractInterceptUrlConfigurer} for further customization
     */
    public C filterSecurityInterceptorOncePerRequest(
            boolean filterSecurityInterceptorOncePerRequest) {
        this.filterSecurityInterceptorOncePerRequest = filterSecurityInterceptorOncePerRequest;
        return getSelf();
    }

    @Override
    public void configure(H http) throws Exception {
        FilterInvocationSecurityMetadataSource metadataSource = createMetadataSource();
        if(metadataSource == null) {
            return;
        }
        FilterSecurityInterceptor securityInterceptor = createFilterSecurityInterceptor(metadataSource, http.getSharedObject(AuthenticationManager.class));
        if(filterSecurityInterceptorOncePerRequest != null) {
            securityInterceptor.setObserveOncePerRequest(filterSecurityInterceptorOncePerRequest);
        }
        securityInterceptor = postProcess(securityInterceptor);
        http.addFilter(securityInterceptor);
        http.setSharedObject(FilterSecurityInterceptor.class, securityInterceptor);
    }

    /**
     * Subclasses should implement this method to provide a {@link FilterInvocationSecurityMetadataSource} for the
     * {@link FilterSecurityInterceptor}.
     *
     * @return the {@link FilterInvocationSecurityMetadataSource} to set on the {@link FilterSecurityInterceptor}.
     *         Cannot be null.
     */
    abstract FilterInvocationSecurityMetadataSource createMetadataSource();

    /**
     * Subclasses should implement this method to provide the {@link AccessDecisionVoter} instances used to create the
     * default {@link AccessDecisionManager}
     *
     * @return the {@link AccessDecisionVoter} instances used to create the
     *         default {@link AccessDecisionManager}
     */
    @SuppressWarnings("rawtypes")
    abstract List<AccessDecisionVoter> getDecisionVoters();

    /**
     * Creates the default {@code AccessDecisionManager}
     * @return the default {@code AccessDecisionManager}
     */
    private AccessDecisionManager createDefaultAccessDecisionManager() {
        return new AffirmativeBased(getDecisionVoters());
    }

    /**
     * If currently null, creates a default {@link AccessDecisionManager} using
     * {@link #createDefaultAccessDecisionManager()}. Otherwise returns the {@link AccessDecisionManager}.
     *
     * @return the {@link AccessDecisionManager} to use
     */
    private AccessDecisionManager getAccessDecisionManager() {
        if (accessDecisionManager == null) {
            accessDecisionManager = createDefaultAccessDecisionManager();
        }
        return accessDecisionManager;
    }

    /**
     * Creates the {@link FilterSecurityInterceptor}
     *
     * @param metadataSource the {@link FilterInvocationSecurityMetadataSource} to use
     * @param authenticationManager the {@link AuthenticationManager} to use
     * @return the {@link FilterSecurityInterceptor}
     * @throws Exception
     */
    private FilterSecurityInterceptor createFilterSecurityInterceptor(FilterInvocationSecurityMetadataSource metadataSource,
                                                                      AuthenticationManager authenticationManager) throws Exception {
        FilterSecurityInterceptor securityInterceptor = new FilterSecurityInterceptor();
        securityInterceptor.setSecurityMetadataSource(metadataSource);
        securityInterceptor.setAccessDecisionManager(getAccessDecisionManager());
        securityInterceptor.setAuthenticationManager(authenticationManager);
        securityInterceptor.afterPropertiesSet();
        return securityInterceptor;
    }

    /**
     * Returns a reference to the current object with a single suppression of
     * the type
     *
     * @return a reference to the current object
     */
    @SuppressWarnings("unchecked")
    private C getSelf() {
        return (C) this;
    }
}