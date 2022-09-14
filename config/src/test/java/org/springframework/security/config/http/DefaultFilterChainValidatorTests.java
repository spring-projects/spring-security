/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.http;

import java.util.Collection;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
public class DefaultFilterChainValidatorTests {

	private DefaultFilterChainValidator validator;

	private FilterChainProxy chain;

	private FilterChainProxy chainAuthorizationFilter;

	@Mock
	private Log logger;

	@Mock
	private DefaultFilterInvocationSecurityMetadataSource metadataSource;

	@Mock
	private AccessDecisionManager accessDecisionManager;

	private FilterSecurityInterceptor authorizationInterceptor;

	@Mock
	private AuthorizationManager<HttpServletRequest> authorizationManager;

	private AuthorizationFilter authorizationFilter;

	@BeforeEach
	public void setUp() {
		AnonymousAuthenticationFilter aaf = new AnonymousAuthenticationFilter("anonymous");
		this.authorizationInterceptor = new FilterSecurityInterceptor();
		this.authorizationInterceptor.setAccessDecisionManager(this.accessDecisionManager);
		this.authorizationInterceptor.setSecurityMetadataSource(this.metadataSource);
		this.authorizationFilter = new AuthorizationFilter(this.authorizationManager);
		AuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/login");
		ExceptionTranslationFilter etf = new ExceptionTranslationFilter(authenticationEntryPoint);
		DefaultSecurityFilterChain securityChain = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, aaf, etf,
				this.authorizationInterceptor);
		this.chain = new FilterChainProxy(securityChain);
		DefaultSecurityFilterChain securityChainAuthorizationFilter = new DefaultSecurityFilterChain(
				AnyRequestMatcher.INSTANCE, aaf, etf, this.authorizationFilter);
		this.chainAuthorizationFilter = new FilterChainProxy(securityChainAuthorizationFilter);
		this.validator = new DefaultFilterChainValidator();
		ReflectionTestUtils.setField(this.validator, "logger", this.logger);
	}

	// SEC-1878
	@SuppressWarnings("unchecked")
	@Test
	public void validateCheckLoginPageIsntProtectedThrowsIllegalArgumentException() {
		IllegalArgumentException toBeThrown = new IllegalArgumentException("failed to eval expression");
		willThrow(toBeThrown).given(this.accessDecisionManager).decide(any(Authentication.class), any(),
				any(Collection.class));
		this.validator.validate(this.chain);
		verify(this.logger).info(
				"Unable to check access to the login page to determine if anonymous access is allowed. This might be an error, but can happen under normal circumstances.",
				toBeThrown);
	}

	@Test
	public void validateCheckLoginPageAllowsAnonymous() {
		given(this.authorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(false));
		this.validator.validate(this.chainAuthorizationFilter);
		verify(this.logger).warn("Anonymous access to the login page doesn't appear to be enabled. "
				+ "This is almost certainly an error. Please check your configuration allows unauthenticated "
				+ "access to the configured login page. (Simulated access was rejected)");
	}

	// SEC-1957
	@Test
	public void validateCustomMetadataSource() {
		FilterInvocationSecurityMetadataSource customMetaDataSource = mock(
				FilterInvocationSecurityMetadataSource.class);
		this.authorizationInterceptor.setSecurityMetadataSource(customMetaDataSource);
		this.validator.validate(this.chain);
		verify(customMetaDataSource, atLeastOnce()).getAttributes(any());
	}

}
