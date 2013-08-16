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

import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.MediaTypeRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * Adds HTTP basic based authentication. All attributes have reasonable defaults
 * making all parameters are optional.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>
 * {@link BasicAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * <ul>
 * <li>AuthenticationEntryPoint - populated with the
 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)} (default
 * {@link BasicAuthenticationEntryPoint})</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link HttpSecurity#getAuthenticationManager()}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class HttpBasicConfigurer<B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<HttpBasicConfigurer<B>,B> {
    private static final String DEFAULT_REALM = "Spring Security Application";

    private AuthenticationEntryPoint authenticationEntryPoint = new BasicAuthenticationEntryPoint();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    /**
     * Creates a new instance
     * @throws Exception
     * @see {@link HttpSecurity#httpBasic()}
     */
    public HttpBasicConfigurer() throws Exception {
        realmName(DEFAULT_REALM);
    }

    /**
     * Shortcut for {@link #authenticationEntryPoint(AuthenticationEntryPoint)}
     * specifying a {@link BasicAuthenticationEntryPoint} with the specified
     * realm name.
     *
     * @param realmName
     *            the HTTP Basic realm to use
     * @return {@link HttpBasicConfigurer} for additional customization
     * @throws Exception
     */
    public HttpBasicConfigurer<B> realmName(String realmName) throws Exception {
        BasicAuthenticationEntryPoint basicAuthEntryPoint = new BasicAuthenticationEntryPoint();
        basicAuthEntryPoint.setRealmName(realmName);
        basicAuthEntryPoint.afterPropertiesSet();
        return authenticationEntryPoint(basicAuthEntryPoint);
    }

    /**
     * The {@link AuthenticationEntryPoint} to be po	pulated on
     * {@link BasicAuthenticationFilter} in the event that authentication fails.
     * The default to use {@link BasicAuthenticationEntryPoint} with the realm
     * "Spring Security Application".
     *
     * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use
     * @return {@link HttpBasicConfigurer} for additional customization
     */
    public HttpBasicConfigurer<B> authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    /**
     * Specifies a custom {@link AuthenticationDetailsSource} to use for basic
     * authentication. The default is {@link WebAuthenticationDetailsSource}.
     *
     * @param authenticationDetailsSource
     *            the custom {@link AuthenticationDetailsSource} to use
     * @return {@link HttpBasicConfigurer} for additional customization
     */
    public HttpBasicConfigurer<B> authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        return this;
    }

    public void init(B http) throws Exception {
        registerDefaultAuthenticationEntryPoint(http);
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultAuthenticationEntryPoint(B http) {
        ExceptionHandlingConfigurer<B> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if(exceptionHandling == null) {
            return;
        }
        ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
        if(contentNegotiationStrategy == null) {
            contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
        }
        MediaTypeRequestMatcher preferredMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.APPLICATION_ATOM_XML, MediaType.APPLICATION_FORM_URLENCODED,  MediaType.APPLICATION_JSON, MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML, MediaType.MULTIPART_FORM_DATA, MediaType.TEXT_XML);
        preferredMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
        exceptionHandling.defaultAuthenticationEntryPointFor(postProcess(authenticationEntryPoint), preferredMatcher);
    }

    @Override
    public void configure(B http) throws Exception {
        AuthenticationManager authenticationManager = http.getAuthenticationManager();
        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager, authenticationEntryPoint);
        if(authenticationDetailsSource != null) {
            basicAuthenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }
        basicAuthenticationFilter = postProcess(basicAuthenticationFilter);
        http.addFilter(basicAuthenticationFilter);
    }
}
