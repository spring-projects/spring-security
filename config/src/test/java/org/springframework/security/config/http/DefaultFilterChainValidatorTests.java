/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.http;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.internal.util.reflection.Whitebox;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

/**
 *
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultFilterChainValidatorTests {
    private DefaultFilterChainValidator validator;
    private FilterChainProxy fcp;
    @Mock
    private Log logger;
    @Mock
    private DefaultFilterInvocationSecurityMetadataSource metadataSource;
    @Mock
    private AccessDecisionManager accessDecisionManager;

    private FilterSecurityInterceptor fsi;

    @Before
    public void setUp() throws Exception {
        AnonymousAuthenticationFilter aaf = new AnonymousAuthenticationFilter("anonymous");
        fsi = new FilterSecurityInterceptor();
        fsi.setAccessDecisionManager(accessDecisionManager);
        fsi.setSecurityMetadataSource(metadataSource);
        AuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/login");
        ExceptionTranslationFilter etf = new ExceptionTranslationFilter(authenticationEntryPoint);
        DefaultSecurityFilterChain securityChain = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, aaf, etf, fsi);
        fcp = new FilterChainProxy(securityChain);
        validator = new DefaultFilterChainValidator();
        Whitebox.setInternalState(validator, "logger", logger);
    }

    // SEC-1878
    @SuppressWarnings("unchecked")
    @Test
    public void validateCheckLoginPageIsntProtectedThrowsIllegalArgumentException() {
        IllegalArgumentException toBeThrown = new IllegalArgumentException("failed to eval expression");
        doThrow(toBeThrown).when(accessDecisionManager).decide(any(Authentication.class), anyObject(), any(Collection.class));
        validator.validate(fcp);
        verify(logger).info("Unable to check access to the login page to determine if anonymous access is allowed. This might be an error, but can happen under normal circumstances.", toBeThrown);
    }

    // SEC-1957
    @Test
    public void validateCustomMetadataSource() {
        FilterInvocationSecurityMetadataSource customMetaDataSource = mock(FilterInvocationSecurityMetadataSource.class);
        fsi.setSecurityMetadataSource(customMetaDataSource);

        validator.validate(fcp);

        verify(customMetaDataSource).getAttributes(any());
    }
}
