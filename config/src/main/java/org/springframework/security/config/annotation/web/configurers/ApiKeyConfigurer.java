/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import java.time.Clock;
import java.util.Collection;
import java.util.Objects;

import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.apikey.ApiKeyAuthenticationProvider;
import org.springframework.security.authentication.apikey.ApiKeyDigest;
import org.springframework.security.authentication.apikey.ApiKeySearchService;
import org.springframework.security.authentication.apikey.ApiKeySimpleGrantedAuthorityConverter;
import org.springframework.security.authentication.apikey.StoredApiKey;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.apikey.ApiKeyAuthenticationFilter;
import org.springframework.security.web.authentication.apikey.BearerTokenAuthenticationConverter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Configures API key authentication.
 *
 * @author Alexey Razinkov
 */
public final class ApiKeyConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<ApiKeyConfigurer<H>, H> {

	private final ApplicationContext context;

	private Clock clock = Clock.systemUTC();

	private Converter<StoredApiKey, Collection<GrantedAuthority>> grantedAuthorityConverter = new ApiKeySimpleGrantedAuthorityConverter();

	private ApiKeySearchService searchService;

	private ApiKeyDigest digest;

	private AuthenticationConverter authnConverter = new BearerTokenAuthenticationConverter();

	private SecurityContextRepository securityContextRepository = new NullSecurityContextRepository();

	private AuthenticationSuccessHandler successHandler;

	private AuthenticationFailureHandler failureHandler;

	public ApiKeyConfigurer(final ApplicationContext context) {
		this.context = Objects.requireNonNull(context);
	}

	public ApiKeyConfigurer<H> clock(final Clock clock) {
		this.clock = Objects.requireNonNull(clock);
		return this;
	}

	public ApiKeyConfigurer<H> grantedAuthorityConverter(
			final Converter<StoredApiKey, Collection<GrantedAuthority>> converter) {
		this.grantedAuthorityConverter = Objects.requireNonNull(converter);
		return this;
	}

	public ApiKeyConfigurer<H> searchService(final ApiKeySearchService searchService) {
		this.searchService = Objects.requireNonNull(searchService);
		return this;
	}

	public ApiKeyConfigurer<H> digest(final ApiKeyDigest digest) {
		this.digest = Objects.requireNonNull(digest);
		return this;
	}

	public ApiKeyConfigurer<H> authenticationConverter(final AuthenticationConverter converter) {
		this.authnConverter = Objects.requireNonNull(converter);
		return this;
	}

	public ApiKeyConfigurer<H> securityContextRepository(final SecurityContextRepository securityContextRepository) {
		this.securityContextRepository = Objects.requireNonNull(securityContextRepository);
		return this;
	}

	public ApiKeyConfigurer<H> authenticationSuccessHandler(final AuthenticationSuccessHandler successHandler) {
		this.successHandler = successHandler;
		return this;
	}

	public ApiKeyConfigurer<H> authenticationFailureHandler(final AuthenticationFailureHandler failureHandler) {
		this.failureHandler = failureHandler;
		return this;
	}

	@Override
	public void init(final H builder) {
		super.init(builder);
		final ApiKeySearchService searchService = getSearchService();
		final ApiKeyDigest digest = getDigest();
		final ApiKeyAuthenticationProvider authnProvider = new ApiKeyAuthenticationProvider(searchService, digest,
				this.clock, this.grantedAuthorityConverter);
		builder.authenticationProvider(authnProvider);
	}

	private ApiKeySearchService getSearchService() {
		if (this.searchService != null) {
			return this.searchService;
		}

		final ApiKeySearchService bean = this.context.getBean(ApiKeySearchService.class);
		if (bean == null) {
			throw new IllegalStateException("API key search service required");
		}

		return bean;
	}

	private ApiKeyDigest getDigest() {
		if (this.digest != null) {
			return this.digest;
		}

		final ApiKeyDigest bean = this.context.getBean(ApiKeyDigest.class);
		if (bean == null) {
			throw new IllegalStateException("API key digest required");
		}

		return bean;
	}

	@Override
	public void configure(final H http) {
		final AuthenticationManager authnManager = http.getSharedObject(AuthenticationManager.class);
		final SecurityContextHolderStrategy securityContextHolderStrategy = getSecurityContextHolderStrategy();
		final ApiKeyAuthenticationFilter filter = new ApiKeyAuthenticationFilter(authnManager, this.authnConverter,
				securityContextHolderStrategy, this.securityContextRepository, this.successHandler,
				this.failureHandler);
		http.addFilter(postProcess(filter));
	}

}
