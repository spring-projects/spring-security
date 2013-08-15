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

import java.util.LinkedHashMap;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.RequestMatcher;

/**
 * Adds exception handling for Spring Security related exceptions to an application. All properties have reasonable
 * defaults, so no additional configuration is required other than applying this
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 *     <li>{@link ExceptionTranslationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 *     <li>If no explicit {@link RequestCache}, is provided a {@link RequestCache} shared object is used to replay
 *     the request after authentication is successful</li>
 *     <li>{@link AuthenticationEntryPoint} - see {@link #authenticationEntryPoint(AuthenticationEntryPoint)} </li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class ExceptionHandlingConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<H> {

    private AuthenticationEntryPoint authenticationEntryPoint;

    private AccessDeniedHandler accessDeniedHandler;

    private LinkedHashMap<RequestMatcher,AuthenticationEntryPoint> defaultEntryPointMappings = new LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>();

    /**
     * Creates a new instance
     * @see HttpSecurity#exceptionHandling()
     */
    public ExceptionHandlingConfigurer() {
    }

    /**
     * Shortcut to specify the {@link AccessDeniedHandler} to be used is a specific error page
     *
     * @param accessDeniedUrl the URL to the access denied page (i.e. /errors/401)
     * @return the {@link ExceptionHandlingConfigurer} for further customization
     * @see AccessDeniedHandlerImpl
     * @see {@link #accessDeniedHandler(org.springframework.security.web.access.AccessDeniedHandler)}
     */
    public ExceptionHandlingConfigurer<H> accessDeniedPage(String accessDeniedUrl) {
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(accessDeniedUrl);
        return accessDeniedHandler(accessDeniedHandler);
    }

    /**
     * Specifies the {@link AccessDeniedHandler} to be used
     *
     * @param accessDeniedHandler the {@link AccessDeniedHandler} to be used
     * @return the {@link ExceptionHandlingConfigurer} for further customization
     */
    public ExceptionHandlingConfigurer<H> accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
        return this;
    }

    /**
     * Sets the {@link AuthenticationEntryPoint} to be used.
     *
     * <p>
     * If no {@link #authenticationEntryPoint(AuthenticationEntryPoint)} is
     * specified, then
     * {@link #defaultAuthenticationEntryPointFor(AuthenticationEntryPoint, RequestMatcher)}
     * will be used. The first {@link AuthenticationEntryPoint} will be used as
     * the default is no matches were found.
     * </p>
     *
     * <p>
     * If that is not provided defaults to {@link Http403ForbiddenEntryPoint}.
     * </p>
     *
     * @param authenticationEntryPoint
     *            the {@link AuthenticationEntryPoint} to use
     * @return the {@link ExceptionHandlingConfigurer} for further
     *         customizations
     */
    public ExceptionHandlingConfigurer<H> authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    /**
     * Sets a default {@link AuthenticationEntryPoint} to be used which prefers
     * being invoked for the provided {@link RequestMatcher}. If only a single
     * default {@link AuthenticationEntryPoint} is specified, it will be what is
     * used for the default {@link AuthenticationEntryPoint}. If multiple
     * default {@link AuthenticationEntryPoint} instances are configured, then a
     * {@link DelegatingAuthenticationEntryPoint} will be used.
     *
     * @param entryPoint
     *            the {@link AuthenticationEntryPoint} to use
     * @param preferredMatcher
     *            the {@link RequestMatcher} for this default
     *            {@link AuthenticationEntryPoint}
     * @return the {@link ExceptionHandlingConfigurer} for further
     *         customizations
     */
    public ExceptionHandlingConfigurer<H> defaultAuthenticationEntryPointFor(AuthenticationEntryPoint entryPoint, RequestMatcher preferredMatcher) {
        this.defaultEntryPointMappings.put(preferredMatcher, entryPoint);
        return this;
    }

    /**
     * Gets any explicitly configured {@link AuthenticationEntryPoint}
     * @return
     */
    AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return this.authenticationEntryPoint;
    }

    /**
     * Gets the {@link AccessDeniedHandler} that is configured.
     *
     * @return the {@link AccessDeniedHandler}
     */
    AccessDeniedHandler getAccessDeniedHandler() {
        return this.accessDeniedHandler;
    }

    @Override
    public void configure(H http) throws Exception {
        AuthenticationEntryPoint entryPoint = getAuthenticationEntryPoint(http);
        ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(entryPoint, getRequestCache(http));
        if(accessDeniedHandler != null) {
            exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler);
        }
        exceptionTranslationFilter = postProcess(exceptionTranslationFilter);
        http.addFilter(exceptionTranslationFilter);
    }
    /**
     * Gets the {@link AuthenticationEntryPoint} according to the rules specified by {@link #authenticationEntryPoint(AuthenticationEntryPoint)}
     * @param http the {@link HttpSecurity} used to look up shared {@link AuthenticationEntryPoint}
     * @return the {@link AuthenticationEntryPoint} to use
     */
     AuthenticationEntryPoint getAuthenticationEntryPoint(H http) {
        AuthenticationEntryPoint entryPoint = this.authenticationEntryPoint;
        if(entryPoint == null) {
            entryPoint = createDefaultEntryPoint(http);
        }
        return entryPoint;
    }

    private AuthenticationEntryPoint createDefaultEntryPoint(H http) {
        if(defaultEntryPointMappings.isEmpty()) {
            return new Http403ForbiddenEntryPoint();
        }
        if(defaultEntryPointMappings.size() == 1) {
            return defaultEntryPointMappings.values().iterator().next();
        }
        DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(defaultEntryPointMappings);
        entryPoint.setDefaultEntryPoint(defaultEntryPointMappings.values().iterator().next());
        return entryPoint;
    }

    /**
     * Gets the {@link RequestCache} to use. If one is defined using
     * {@link #requestCache(org.springframework.security.web.savedrequest.RequestCache)}, then it is used. Otherwise, an
     * attempt to find a {@link RequestCache} shared object is made. If that fails, an {@link HttpSessionRequestCache}
     * is used
     *
     * @param http the {@link HttpSecurity} to attempt to fined the shared object
     * @return the {@link RequestCache} to use
     */
    private RequestCache getRequestCache(H http) {
        RequestCache result = http.getSharedObject(RequestCache.class);
        if(result != null) {
            return result;
        }
        return new HttpSessionRequestCache();
    }
}
