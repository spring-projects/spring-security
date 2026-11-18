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

package org.springframework.security.authentication.apikey;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

/**
 * API key authentication provider.
 *
 * @author Alexey Razinkov
 */
public final class ApiKeyAuthenticationProvider implements AuthenticationProvider {

	private final ApiKeySearchService searchService;

	private final ApiKeyDigest digest;

	private final Clock clock;

	private final Converter<StoredApiKey, Collection<GrantedAuthority>> grantedAuthorityConverter;

	public ApiKeyAuthenticationProvider(final ApiKeySearchService searchService, final ApiKeyDigest digest,
			final Clock clock, final Converter<StoredApiKey, Collection<GrantedAuthority>> grantedAuthorityConverter) {
		this.searchService = Objects.requireNonNull(searchService);
		this.digest = Objects.requireNonNull(digest);
		this.clock = Objects.requireNonNull(clock);
		this.grantedAuthorityConverter = Objects.requireNonNull(grantedAuthorityConverter);
	}

	@Override
	public @Nullable Authentication authenticate(final Authentication authentication) throws AuthenticationException {
		final ApiKeyToken apiKeyToken = (ApiKeyToken) authentication;
		final ApiKey apiKey = apiKeyToken.getValue();

		final StoredApiKey storedApiKey = this.searchService.findApiKeyHash(apiKey.getId());
		if (storedApiKey == null) {
			// mitigating timing attack by comparing secret against some dummy hash
			final String dummy = this.digest.getDummyDigest();
			this.digest.matches(apiKey.getSecret(), dummy);

			throw new ApiKeyAuthenticationException.NotFound(apiKey.getId());
		}

		if (!this.digest.matches(apiKey.getSecret(), storedApiKey.secretHash())) {
			throw new BadCredentialsException("API key secret does not match");
		}

		final Instant expiresAt = storedApiKey.expiresAt();
		if (expiresAt != null) {
			final Instant now = this.clock.instant();
			if (expiresAt.isBefore(now)) {
				throw new ApiKeyAuthenticationException.Expired(apiKey.getId(), expiresAt, now);
			}
		}

		final Collection<GrantedAuthority> authorities = this.grantedAuthorityConverter.convert(storedApiKey);
		return new AuthenticatedApiKeyToken(apiKey, authorities, apiKeyToken.getDetails());
	}

	@Override
	public boolean supports(final Class<?> authentication) {
		return ApiKeyToken.class.isAssignableFrom(authentication);
	}

}
