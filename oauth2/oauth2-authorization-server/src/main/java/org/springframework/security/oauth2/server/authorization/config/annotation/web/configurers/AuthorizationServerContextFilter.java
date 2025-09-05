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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} that associates the {@link AuthorizationServerContext} to the
 * {@link AuthorizationServerContextHolder}.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerContext
 * @see AuthorizationServerContextHolder
 * @see AuthorizationServerSettings
 */
final class AuthorizationServerContextFilter extends OncePerRequestFilter {

	private final AuthorizationServerSettings authorizationServerSettings;

	private final IssuerResolver issuerResolver;

	AuthorizationServerContextFilter(AuthorizationServerSettings authorizationServerSettings) {
		Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
		this.authorizationServerSettings = authorizationServerSettings;
		this.issuerResolver = new IssuerResolver(authorizationServerSettings);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			String issuer = this.issuerResolver.resolve(request);
			AuthorizationServerContext authorizationServerContext = new DefaultAuthorizationServerContext(issuer,
					this.authorizationServerSettings);
			AuthorizationServerContextHolder.setContext(authorizationServerContext);
			filterChain.doFilter(request, response);
		}
		finally {
			AuthorizationServerContextHolder.resetContext();
		}
	}

	private static final class IssuerResolver {

		private final String issuer;

		private final Set<String> endpointUris;

		private IssuerResolver(AuthorizationServerSettings authorizationServerSettings) {
			if (authorizationServerSettings.getIssuer() != null) {
				this.issuer = authorizationServerSettings.getIssuer();
				this.endpointUris = Collections.emptySet();
			}
			else {
				this.issuer = null;
				this.endpointUris = new HashSet<>();
				this.endpointUris.add("/.well-known/oauth-authorization-server");
				this.endpointUris.add("/.well-known/openid-configuration");
				for (Map.Entry<String, Object> setting : authorizationServerSettings.getSettings().entrySet()) {
					if (setting.getKey().endsWith("-endpoint")) {
						this.endpointUris.add((String) setting.getValue());
					}
				}
			}
		}

		private String resolve(HttpServletRequest request) {
			if (this.issuer != null) {
				return this.issuer;
			}

			// Resolve Issuer Identifier dynamically from request
			String path = request.getRequestURI();
			if (!StringUtils.hasText(path)) {
				path = "";
			}
			else {
				for (String endpointUri : this.endpointUris) {
					if (path.contains(endpointUri)) {
						path = path.replace(endpointUri, "");
						break;
					}
				}
			}

			// @formatter:off
			return UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
					.replacePath(path)
					.replaceQuery(null)
					.fragment(null)
					.build()
					.toUriString();
			// @formatter:on
		}

	}

	private static final class DefaultAuthorizationServerContext implements AuthorizationServerContext {

		private final String issuer;

		private final AuthorizationServerSettings authorizationServerSettings;

		private DefaultAuthorizationServerContext(String issuer,
				AuthorizationServerSettings authorizationServerSettings) {
			this.issuer = issuer;
			this.authorizationServerSettings = authorizationServerSettings;
		}

		@Override
		public String getIssuer() {
			return this.issuer;
		}

		@Override
		public AuthorizationServerSettings getAuthorizationServerSettings() {
			return this.authorizationServerSettings;
		}

	}

}
