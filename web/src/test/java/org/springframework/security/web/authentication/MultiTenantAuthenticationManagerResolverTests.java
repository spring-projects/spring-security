/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.web.authentication;

import java.util.Collections;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.web.authentication.MultiTenantAuthenticationManagerResolver.resolveFromSubdomain;
import static org.springframework.security.web.authentication.MultiTenantAuthenticationManagerResolver.resolveFromPath;
import static org.springframework.security.web.authentication.MultiTenantAuthenticationManagerResolver.resolveFromHeader;

/**
 * Tests for {@link MultiTenantAuthenticationManagerResolver}
 */
@RunWith(MockitoJUnitRunner.class)
public class MultiTenantAuthenticationManagerResolverTests {
	private static final String TENANT = "tenant";

	@Mock
	AuthenticationManager authenticationManager;

	@Mock
	HttpServletRequest request;

	Map<String, AuthenticationManager> authenticationManagers;

	@Before
	public void setup() {
		this.authenticationManagers = Collections.singletonMap(TENANT, this.authenticationManager);
	}

	@Test
	public void resolveFromSubdomainWhenGivenResolverThenReturnsSubdomainParsingResolver() {
		AuthenticationManagerResolver<HttpServletRequest> fromSubdomain =
				resolveFromSubdomain(this.authenticationManagers::get);

		when(this.request.getServerName()).thenReturn(TENANT + ".example.org");

		AuthenticationManager authenticationManager = fromSubdomain.resolve(this.request);
		assertThat(authenticationManager).isEqualTo(this.authenticationManager);

		when(this.request.getServerName()).thenReturn("wrong.example.org");

		assertThatCode(() -> fromSubdomain.resolve(this.request))
				.isInstanceOf(IllegalArgumentException.class);

		when(this.request.getServerName()).thenReturn("example");

		assertThatCode(() -> fromSubdomain.resolve(this.request))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void resolveFromPathWhenGivenResolverThenReturnsPathParsingResolver() {
		AuthenticationManagerResolver<HttpServletRequest> fromPath =
				resolveFromPath(this.authenticationManagers::get);

		when(this.request.getRequestURI()).thenReturn("/" + TENANT + "/otherthings");

		AuthenticationManager authenticationManager = fromPath.resolve(this.request);
		assertThat(authenticationManager).isEqualTo(this.authenticationManager);

		when(this.request.getRequestURI()).thenReturn("/otherthings");

		assertThatCode(() -> fromPath.resolve(this.request))
				.isInstanceOf(IllegalArgumentException.class);

		when(this.request.getRequestURI()).thenReturn("/");

		assertThatCode(() -> fromPath.resolve(this.request))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void resolveFromHeaderWhenGivenResolverTheReturnsHeaderParsingResolver() {
		AuthenticationManagerResolver<HttpServletRequest> fromHeader =
				resolveFromHeader("X-Tenant-Id", this.authenticationManagers::get);

		when(this.request.getHeader("X-Tenant-Id")).thenReturn(TENANT);

		AuthenticationManager authenticationManager = fromHeader.resolve(this.request);
		assertThat(authenticationManager).isEqualTo(this.authenticationManager);

		when(this.request.getHeader("X-Tenant-Id")).thenReturn("wrong");

		assertThatCode(() -> fromHeader.resolve(this.request))
				.isInstanceOf(IllegalArgumentException.class);

		when(this.request.getHeader("X-Tenant-Id")).thenReturn(null);

		assertThatCode(() -> fromHeader.resolve(this.request))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void resolveWhenGivenTenantResolverThenResolves() {
		AuthenticationManagerResolver<HttpServletRequest> byRequestConverter =
				new MultiTenantAuthenticationManagerResolver<>(HttpServletRequest::getQueryString,
						this.authenticationManagers::get);

		when(this.request.getQueryString()).thenReturn(TENANT);

		AuthenticationManager authenticationManager = byRequestConverter.resolve(this.request);
		assertThat(authenticationManager).isEqualTo(this.authenticationManager);

		when(this.request.getQueryString()).thenReturn("wrong");

		assertThatCode(() -> byRequestConverter.resolve(this.request))
				.isInstanceOf(IllegalArgumentException.class);

		when(this.request.getQueryString()).thenReturn(null);

		assertThatCode(() -> byRequestConverter.resolve(this.request))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenUsingNullTenantResolverThenException() {
		assertThatCode(() -> new MultiTenantAuthenticationManagerResolver
				(null, mock(Converter.class)))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenUsingNullAuthenticationManagerResolverThenException() {
		assertThatCode(() -> new MultiTenantAuthenticationManagerResolver
				(mock(Converter.class), null))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
