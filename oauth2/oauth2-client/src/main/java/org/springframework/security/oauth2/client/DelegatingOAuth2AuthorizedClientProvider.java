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
package org.springframework.security.oauth2.client;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * An implementation of an {@link OAuth2AuthorizedClientProvider} that simply delegates
 * to it's internal {@code List} of {@link OAuth2AuthorizedClientProvider}(s).
 * <p>
 * Each provider is given a chance to
 * {@link OAuth2AuthorizedClientProvider#authorize(OAuth2AuthorizationContext) authorize}
 * the {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided context
 * with the first {@code non-null} {@link OAuth2AuthorizedClient} being returned.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientProvider
 */
public final class DelegatingOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {
	private final List<OAuth2AuthorizedClientProvider> authorizedClientProviders;

	/**
	 * Constructs a {@code DelegatingOAuth2AuthorizedClientProvider} using the provided parameters.
	 *
	 * @param authorizedClientProviders a list of {@link OAuth2AuthorizedClientProvider}(s)
	 */
	public DelegatingOAuth2AuthorizedClientProvider(OAuth2AuthorizedClientProvider... authorizedClientProviders) {
		Assert.notEmpty(authorizedClientProviders, "authorizedClientProviders cannot be empty");
		this.authorizedClientProviders = Collections.unmodifiableList(Arrays.asList(authorizedClientProviders));
	}

	/**
	 * Constructs a {@code DelegatingOAuth2AuthorizedClientProvider} using the provided parameters.
	 *
	 * @param authorizedClientProviders a {@code List} of {@link OAuth2AuthorizedClientProvider}(s)
	 */
	public DelegatingOAuth2AuthorizedClientProvider(List<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		Assert.notEmpty(authorizedClientProviders, "authorizedClientProviders cannot be empty");
		this.authorizedClientProviders = Collections.unmodifiableList(new ArrayList<>(authorizedClientProviders));
	}

	@Override
	@Nullable
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		for (OAuth2AuthorizedClientProvider authorizedClientProvider : authorizedClientProviders) {
			OAuth2AuthorizedClient oauth2AuthorizedClient = authorizedClientProvider.authorize(context);
			if (oauth2AuthorizedClient != null) {
				return oauth2AuthorizedClient;
			}
		}
		return null;
	}
}
