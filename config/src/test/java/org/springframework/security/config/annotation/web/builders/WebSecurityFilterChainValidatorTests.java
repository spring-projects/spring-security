/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.UnreachableFilterChainException;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatchers;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link WebSecurityFilterChainValidator}
 *
 * @author Max Batischev
 */
@ExtendWith(MockitoExtension.class)
public class WebSecurityFilterChainValidatorTests {

	private final WebSecurityFilterChainValidator validator = new WebSecurityFilterChainValidator();

	@Mock
	private AnonymousAuthenticationFilter authenticationFilter;

	@Mock
	private ExceptionTranslationFilter exceptionTranslationFilter;

	@Mock
	private FilterSecurityInterceptor authorizationInterceptor;

	@Test
	void validateWhenFilterSecurityInterceptorConfiguredThenValidates() {
		SecurityFilterChain chain = new DefaultSecurityFilterChain(AntPathRequestMatcher.antMatcher("/api"),
				this.authenticationFilter, this.exceptionTranslationFilter, this.authorizationInterceptor);
		FilterChainProxy proxy = new FilterChainProxy(List.of(chain));

		assertThatNoException().isThrownBy(() -> this.validator.validate(proxy));
	}

	@Test
	void validateWhenAnyRequestMatcherIsPresentThenUnreachableFilterChainException() {
		SecurityFilterChain chain1 = new DefaultSecurityFilterChain(AntPathRequestMatcher.antMatcher("/api"),
				this.authenticationFilter, this.exceptionTranslationFilter, this.authorizationInterceptor);
		SecurityFilterChain chain2 = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE,
				this.authenticationFilter, this.exceptionTranslationFilter, this.authorizationInterceptor);
		List<SecurityFilterChain> chains = new ArrayList<>();
		chains.add(chain2);
		chains.add(chain1);
		FilterChainProxy proxy = new FilterChainProxy(chains);

		assertThatExceptionOfType(UnreachableFilterChainException.class)
			.isThrownBy(() -> this.validator.validate(proxy));
	}

	@Test
	void validateWhenSameRequestMatchersArePresentThenUnreachableFilterChainException() {
		SecurityFilterChain chain1 = new DefaultSecurityFilterChain(AntPathRequestMatcher.antMatcher("/api"),
				this.authenticationFilter, this.exceptionTranslationFilter, this.authorizationInterceptor);
		SecurityFilterChain chain2 = new DefaultSecurityFilterChain(AntPathRequestMatcher.antMatcher("/api"),
				this.authenticationFilter, this.exceptionTranslationFilter, this.authorizationInterceptor);
		List<SecurityFilterChain> chains = new ArrayList<>();
		chains.add(chain2);
		chains.add(chain1);
		FilterChainProxy proxy = new FilterChainProxy(chains);

		assertThatExceptionOfType(UnreachableFilterChainException.class)
			.isThrownBy(() -> this.validator.validate(proxy));
	}

	@Test
	void validateWhenSameComposedRequestMatchersArePresentThenUnreachableFilterChainException() {
		RequestMatcher matcher1 = RequestMatchers.anyOf(RequestMatchers.allOf(AntPathRequestMatcher.antMatcher("/api"),
				AntPathRequestMatcher.antMatcher("*.do")), AntPathRequestMatcher.antMatcher("/admin"));
		RequestMatcher matcher2 = RequestMatchers.anyOf(RequestMatchers.allOf(AntPathRequestMatcher.antMatcher("/api"),
				AntPathRequestMatcher.antMatcher("*.do")), AntPathRequestMatcher.antMatcher("/admin"));
		SecurityFilterChain chain1 = new DefaultSecurityFilterChain(matcher1, this.authenticationFilter,
				this.exceptionTranslationFilter, this.authorizationInterceptor);
		SecurityFilterChain chain2 = new DefaultSecurityFilterChain(matcher2, this.authenticationFilter,
				this.exceptionTranslationFilter, this.authorizationInterceptor);
		List<SecurityFilterChain> chains = new ArrayList<>();
		chains.add(chain2);
		chains.add(chain1);
		FilterChainProxy proxy = new FilterChainProxy(chains);

		assertThatExceptionOfType(UnreachableFilterChainException.class)
			.isThrownBy(() -> this.validator.validate(proxy));
	}

}
