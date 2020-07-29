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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.util.Assert;

/**
 * A builder that builds a {@link DelegatingReactiveOAuth2AuthorizedClientProvider}
 * composed of one or more {@link ReactiveOAuth2AuthorizedClientProvider}(s) that
 * implement specific authorization grants. The supported authorization grants are
 * {@link #authorizationCode() authorization_code}, {@link #refreshToken() refresh_token},
 * {@link #clientCredentials() client_credentials} and {@link #password() password}. In
 * addition to the standard authorization grants, an implementation of an extension grant
 * may be supplied via {@link #provider(ReactiveOAuth2AuthorizedClientProvider)}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see ReactiveOAuth2AuthorizedClientProvider
 * @see AuthorizationCodeReactiveOAuth2AuthorizedClientProvider
 * @see RefreshTokenReactiveOAuth2AuthorizedClientProvider
 * @see ClientCredentialsReactiveOAuth2AuthorizedClientProvider
 * @see PasswordReactiveOAuth2AuthorizedClientProvider
 * @see DelegatingReactiveOAuth2AuthorizedClientProvider
 */
public final class ReactiveOAuth2AuthorizedClientProviderBuilder {

	private final Map<Class<?>, Builder> builders = new LinkedHashMap<>();

	private ReactiveOAuth2AuthorizedClientProviderBuilder() {
	}

	/**
	 * Returns a new {@link ReactiveOAuth2AuthorizedClientProviderBuilder} for configuring
	 * the supported authorization grant(s).
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public static ReactiveOAuth2AuthorizedClientProviderBuilder builder() {
		return new ReactiveOAuth2AuthorizedClientProviderBuilder();
	}

	/**
	 * Configures a {@link ReactiveOAuth2AuthorizedClientProvider} to be composed with the
	 * {@link DelegatingReactiveOAuth2AuthorizedClientProvider}. This may be used for
	 * implementations of extension authorization grants.
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public ReactiveOAuth2AuthorizedClientProviderBuilder provider(ReactiveOAuth2AuthorizedClientProvider provider) {
		Assert.notNull(provider, "provider cannot be null");
		this.builders.computeIfAbsent(provider.getClass(), k -> () -> provider);
		return ReactiveOAuth2AuthorizedClientProviderBuilder.this;
	}

	/**
	 * Configures support for the {@code authorization_code} grant.
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public ReactiveOAuth2AuthorizedClientProviderBuilder authorizationCode() {
		this.builders.computeIfAbsent(AuthorizationCodeReactiveOAuth2AuthorizedClientProvider.class,
				k -> new AuthorizationCodeGrantBuilder());
		return ReactiveOAuth2AuthorizedClientProviderBuilder.this;
	}

	/**
	 * Configures support for the {@code refresh_token} grant.
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public ReactiveOAuth2AuthorizedClientProviderBuilder refreshToken() {
		this.builders.computeIfAbsent(RefreshTokenReactiveOAuth2AuthorizedClientProvider.class,
				k -> new RefreshTokenGrantBuilder());
		return ReactiveOAuth2AuthorizedClientProviderBuilder.this;
	}

	/**
	 * Configures support for the {@code refresh_token} grant.
	 * @param builderConsumer a {@code Consumer} of {@link RefreshTokenGrantBuilder} used
	 * for further configuration
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public ReactiveOAuth2AuthorizedClientProviderBuilder refreshToken(
			Consumer<RefreshTokenGrantBuilder> builderConsumer) {
		RefreshTokenGrantBuilder builder = (RefreshTokenGrantBuilder) this.builders.computeIfAbsent(
				RefreshTokenReactiveOAuth2AuthorizedClientProvider.class, k -> new RefreshTokenGrantBuilder());
		builderConsumer.accept(builder);
		return ReactiveOAuth2AuthorizedClientProviderBuilder.this;
	}

	/**
	 * Configures support for the {@code client_credentials} grant.
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public ReactiveOAuth2AuthorizedClientProviderBuilder clientCredentials() {
		this.builders.computeIfAbsent(ClientCredentialsReactiveOAuth2AuthorizedClientProvider.class,
				k -> new ClientCredentialsGrantBuilder());
		return ReactiveOAuth2AuthorizedClientProviderBuilder.this;
	}

	/**
	 * Configures support for the {@code client_credentials} grant.
	 * @param builderConsumer a {@code Consumer} of {@link ClientCredentialsGrantBuilder}
	 * used for further configuration
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public ReactiveOAuth2AuthorizedClientProviderBuilder clientCredentials(
			Consumer<ClientCredentialsGrantBuilder> builderConsumer) {
		ClientCredentialsGrantBuilder builder = (ClientCredentialsGrantBuilder) this.builders.computeIfAbsent(
				ClientCredentialsReactiveOAuth2AuthorizedClientProvider.class,
				k -> new ClientCredentialsGrantBuilder());
		builderConsumer.accept(builder);
		return ReactiveOAuth2AuthorizedClientProviderBuilder.this;
	}

	/**
	 * Configures support for the {@code password} grant.
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public ReactiveOAuth2AuthorizedClientProviderBuilder password() {
		this.builders.computeIfAbsent(PasswordReactiveOAuth2AuthorizedClientProvider.class,
				k -> new PasswordGrantBuilder());
		return ReactiveOAuth2AuthorizedClientProviderBuilder.this;
	}

	/**
	 * Configures support for the {@code password} grant.
	 * @param builderConsumer a {@code Consumer} of {@link PasswordGrantBuilder} used for
	 * further configuration
	 * @return the {@link ReactiveOAuth2AuthorizedClientProviderBuilder}
	 */
	public ReactiveOAuth2AuthorizedClientProviderBuilder password(Consumer<PasswordGrantBuilder> builderConsumer) {
		PasswordGrantBuilder builder = (PasswordGrantBuilder) this.builders
				.computeIfAbsent(PasswordReactiveOAuth2AuthorizedClientProvider.class, k -> new PasswordGrantBuilder());
		builderConsumer.accept(builder);
		return ReactiveOAuth2AuthorizedClientProviderBuilder.this;
	}

	/**
	 * Builds an instance of {@link DelegatingReactiveOAuth2AuthorizedClientProvider}
	 * composed of one or more {@link ReactiveOAuth2AuthorizedClientProvider}(s).
	 * @return the {@link DelegatingReactiveOAuth2AuthorizedClientProvider}
	 */
	public ReactiveOAuth2AuthorizedClientProvider build() {
		List<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders = this.builders.values().stream()
				.map(Builder::build).collect(Collectors.toList());
		return new DelegatingReactiveOAuth2AuthorizedClientProvider(authorizedClientProviders);
	}

	interface Builder {

		ReactiveOAuth2AuthorizedClientProvider build();

	}

	/**
	 * A builder for the {@code authorization_code} grant.
	 */
	public final class AuthorizationCodeGrantBuilder implements Builder {

		private AuthorizationCodeGrantBuilder() {
		}

		/**
		 * Builds an instance of
		 * {@link AuthorizationCodeReactiveOAuth2AuthorizedClientProvider}.
		 * @return the {@link AuthorizationCodeReactiveOAuth2AuthorizedClientProvider}
		 */
		@Override
		public ReactiveOAuth2AuthorizedClientProvider build() {
			return new AuthorizationCodeReactiveOAuth2AuthorizedClientProvider();
		}

	}

	/**
	 * A builder for the {@code client_credentials} grant.
	 */
	public final class ClientCredentialsGrantBuilder implements Builder {

		private ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient;

		private Duration clockSkew;

		private Clock clock;

		private ClientCredentialsGrantBuilder() {
		}

		/**
		 * Sets the client used when requesting an access token credential at the Token
		 * Endpoint.
		 * @param accessTokenResponseClient the client used when requesting an access
		 * token credential at the Token Endpoint
		 * @return the {@link ClientCredentialsGrantBuilder}
		 */
		public ClientCredentialsGrantBuilder accessTokenResponseClient(
				ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient) {
			this.accessTokenResponseClient = accessTokenResponseClient;
			return this;
		}

		/**
		 * Sets the maximum acceptable clock skew, which is used when checking the access
		 * token expiry. An access token is considered expired if it's before
		 * {@code Instant.now(this.clock) - clockSkew}.
		 * @param clockSkew the maximum acceptable clock skew
		 * @return the {@link ClientCredentialsGrantBuilder}
		 */
		public ClientCredentialsGrantBuilder clockSkew(Duration clockSkew) {
			this.clockSkew = clockSkew;
			return this;
		}

		/**
		 * Sets the {@link Clock} used in {@link Instant#now(Clock)} when checking the
		 * access token expiry.
		 * @param clock the clock
		 * @return the {@link ClientCredentialsGrantBuilder}
		 */
		public ClientCredentialsGrantBuilder clock(Clock clock) {
			this.clock = clock;
			return this;
		}

		/**
		 * Builds an instance of
		 * {@link ClientCredentialsReactiveOAuth2AuthorizedClientProvider}.
		 * @return the {@link ClientCredentialsReactiveOAuth2AuthorizedClientProvider}
		 */
		@Override
		public ReactiveOAuth2AuthorizedClientProvider build() {
			ClientCredentialsReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
			if (this.accessTokenResponseClient != null) {
				authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
			}
			if (this.clockSkew != null) {
				authorizedClientProvider.setClockSkew(this.clockSkew);
			}
			if (this.clock != null) {
				authorizedClientProvider.setClock(this.clock);
			}
			return authorizedClientProvider;
		}

	}

	/**
	 * A builder for the {@code password} grant.
	 */
	public final class PasswordGrantBuilder implements Builder {

		private ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient;

		private Duration clockSkew;

		private Clock clock;

		private PasswordGrantBuilder() {
		}

		/**
		 * Sets the client used when requesting an access token credential at the Token
		 * Endpoint.
		 * @param accessTokenResponseClient the client used when requesting an access
		 * token credential at the Token Endpoint
		 * @return the {@link PasswordGrantBuilder}
		 */
		public PasswordGrantBuilder accessTokenResponseClient(
				ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient) {
			this.accessTokenResponseClient = accessTokenResponseClient;
			return this;
		}

		/**
		 * Sets the maximum acceptable clock skew, which is used when checking the access
		 * token expiry. An access token is considered expired if it's before
		 * {@code Instant.now(this.clock) - clockSkew}.
		 * @param clockSkew the maximum acceptable clock skew
		 * @return the {@link PasswordGrantBuilder}
		 */
		public PasswordGrantBuilder clockSkew(Duration clockSkew) {
			this.clockSkew = clockSkew;
			return this;
		}

		/**
		 * Sets the {@link Clock} used in {@link Instant#now(Clock)} when checking the
		 * access token expiry.
		 * @param clock the clock
		 * @return the {@link PasswordGrantBuilder}
		 */
		public PasswordGrantBuilder clock(Clock clock) {
			this.clock = clock;
			return this;
		}

		/**
		 * Builds an instance of {@link PasswordReactiveOAuth2AuthorizedClientProvider}.
		 * @return the {@link PasswordReactiveOAuth2AuthorizedClientProvider}
		 */
		@Override
		public ReactiveOAuth2AuthorizedClientProvider build() {
			PasswordReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new PasswordReactiveOAuth2AuthorizedClientProvider();
			if (this.accessTokenResponseClient != null) {
				authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
			}
			if (this.clockSkew != null) {
				authorizedClientProvider.setClockSkew(this.clockSkew);
			}
			if (this.clock != null) {
				authorizedClientProvider.setClock(this.clock);
			}
			return authorizedClientProvider;
		}

	}

	/**
	 * A builder for the {@code refresh_token} grant.
	 */
	public final class RefreshTokenGrantBuilder implements Builder {

		private ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient;

		private Duration clockSkew;

		private Clock clock;

		private RefreshTokenGrantBuilder() {
		}

		/**
		 * Sets the client used when requesting an access token credential at the Token
		 * Endpoint.
		 * @param accessTokenResponseClient the client used when requesting an access
		 * token credential at the Token Endpoint
		 * @return the {@link RefreshTokenGrantBuilder}
		 */
		public RefreshTokenGrantBuilder accessTokenResponseClient(
				ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient) {
			this.accessTokenResponseClient = accessTokenResponseClient;
			return this;
		}

		/**
		 * Sets the maximum acceptable clock skew, which is used when checking the access
		 * token expiry. An access token is considered expired if it's before
		 * {@code Instant.now(this.clock) - clockSkew}.
		 * @param clockSkew the maximum acceptable clock skew
		 * @return the {@link RefreshTokenGrantBuilder}
		 */
		public RefreshTokenGrantBuilder clockSkew(Duration clockSkew) {
			this.clockSkew = clockSkew;
			return this;
		}

		/**
		 * Sets the {@link Clock} used in {@link Instant#now(Clock)} when checking the
		 * access token expiry.
		 * @param clock the clock
		 * @return the {@link RefreshTokenGrantBuilder}
		 */
		public RefreshTokenGrantBuilder clock(Clock clock) {
			this.clock = clock;
			return this;
		}

		/**
		 * Builds an instance of
		 * {@link RefreshTokenReactiveOAuth2AuthorizedClientProvider}.
		 * @return the {@link RefreshTokenReactiveOAuth2AuthorizedClientProvider}
		 */
		@Override
		public ReactiveOAuth2AuthorizedClientProvider build() {
			RefreshTokenReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new RefreshTokenReactiveOAuth2AuthorizedClientProvider();
			if (this.accessTokenResponseClient != null) {
				authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
			}
			if (this.clockSkew != null) {
				authorizedClientProvider.setClockSkew(this.clockSkew);
			}
			if (this.clock != null) {
				authorizedClientProvider.setClock(this.clock);
			}
			return authorizedClientProvider;
		}

	}

}
