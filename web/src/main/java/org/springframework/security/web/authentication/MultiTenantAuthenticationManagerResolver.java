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

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An implementation of {@link AuthenticationManagerResolver} that separates the tasks of
 * extracting the request's tenant identifier and looking up an {@link AuthenticationManager}
 * by that tenant identifier.
 *
 * @author Josh Cummings
 * @since 5.2
 * @see AuthenticationManagerResolver
 */
public final class MultiTenantAuthenticationManagerResolver<T> implements AuthenticationManagerResolver<HttpServletRequest> {

	private final Converter<HttpServletRequest, AuthenticationManager> authenticationManagerResolver;

	/**
	 * Constructs a {@link MultiTenantAuthenticationManagerResolver} with the provided parameters
	 *
	 * @param tenantResolver
	 * @param authenticationManagerResolver
	 */
	public MultiTenantAuthenticationManagerResolver
			(Converter<HttpServletRequest, T> tenantResolver,
					Converter<T, AuthenticationManager> authenticationManagerResolver) {

		Assert.notNull(tenantResolver, "tenantResolver cannot be null");
		Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");

		this.authenticationManagerResolver = request -> {
			Optional<T> context = Optional.ofNullable(tenantResolver.convert(request));
			return context.map(authenticationManagerResolver::convert)
					.orElseThrow(() -> new IllegalArgumentException
							("Could not resolve AuthenticationManager by reference " + context.orElse(null)));
		};
	}

	@Override
	public AuthenticationManager resolve(HttpServletRequest context) {
		return this.authenticationManagerResolver.convert(context);
	}

	/**
	 * Creates an {@link AuthenticationManagerResolver} that will use a hostname's first label as
	 * the resolution key for the underlying {@link AuthenticationManagerResolver}.
	 *
	 * For example, you might have a set of {@link AuthenticationManager}s defined like so:
	 *
	 * <pre>
	 * 	Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
	 *  authenticationManagers.put("tenantOne", managerOne());
	 *  authenticationManagers.put("tenantTwo", managerTwo());
	 * </pre>
	 *
	 * And that your system serves hostnames like <pre>https://tenantOne.example.org</pre>.
	 *
	 * Then, you could create an {@link AuthenticationManagerResolver} that uses the "tenantOne" value from
	 * the hostname to resolve Tenant One's {@link AuthenticationManager} like so:
	 *
	 * <pre>
	 *	AuthenticationManagerResolver<HttpServletRequest> resolver =
	 *			resolveFromSubdomain(authenticationManagers::get);
	 * </pre>
	 *
	 * {@link HttpServletRequest}
	 * @param resolver A {@link String}-resolving {@link AuthenticationManagerResolver}
	 * @return A hostname-resolving {@link AuthenticationManagerResolver}
	 */
	public static AuthenticationManagerResolver<HttpServletRequest>
			resolveFromSubdomain(Converter<String, AuthenticationManager> resolver) {

		return new MultiTenantAuthenticationManagerResolver<>(request ->
				Optional.ofNullable(request.getServerName())
						.map(host -> host.split("\\."))
						.filter(segments -> segments.length > 0)
						.map(segments -> segments[0]).orElse(null), resolver);
	}

	/**
	 * Creates an {@link AuthenticationManagerResolver} that will use a request path's first segment as
	 * the resolution key for the underlying {@link AuthenticationManagerResolver}.
	 *
	 * For example, you might have a set of {@link AuthenticationManager}s defined like so:
	 *
	 * <pre>
	 * 	Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
	 *  authenticationManagers.put("tenantOne", managerOne());
	 *  authenticationManagers.put("tenantTwo", managerTwo());
	 * </pre>
	 *
	 * And that your system serves requests like <pre>https://example.org/tenantOne</pre>.
	 *
	 * Then, you could create an {@link AuthenticationManagerResolver} that uses the "tenantOne" value from
	 * the request to resolve Tenant One's {@link AuthenticationManager} like so:
	 *
	 * <pre>
	 *	AuthenticationManagerResolver<HttpServletRequest> resolver =
	 *			resolveFromPath(authenticationManagers::get);
	 * </pre>
	 *
	 * {@link HttpServletRequest}
	 * @param resolver A {@link String}-resolving {@link AuthenticationManagerResolver}
	 * @return A path-resolving {@link AuthenticationManagerResolver}
	 */
	public static AuthenticationManagerResolver<HttpServletRequest>
			resolveFromPath(Converter<String, AuthenticationManager> resolver) {

		return new MultiTenantAuthenticationManagerResolver<>(request ->
			Optional.ofNullable(request.getRequestURI())
					.map(UriComponentsBuilder::fromUriString)
					.map(UriComponentsBuilder::build)
					.map(UriComponents::getPathSegments)
					.filter(segments -> !segments.isEmpty())
					.map(segments -> segments.get(0)).orElse(null), resolver);
	}

	/**
	 * Creates an {@link AuthenticationManagerResolver} that will use a request headers's value as
	 * the resolution key for the underlying {@link AuthenticationManagerResolver}.
	 *
	 * For example, you might have a set of {@link AuthenticationManager}s defined like so:
	 *
	 * <pre>
	 * 	Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
	 *  authenticationManagers.put("tenantOne", managerOne());
	 *  authenticationManagers.put("tenantTwo", managerTwo());
	 * </pre>
	 *
	 * And that your system serves requests with a header like <pre>X-Tenant-Id: tenantOne</pre>.
	 *
	 * Then, you could create an {@link AuthenticationManagerResolver} that uses the "tenantOne" value from
	 * the request to resolve Tenant One's {@link AuthenticationManager} like so:
	 *
	 * <pre>
	 *	AuthenticationManagerResolver<HttpServletRequest> resolver =
	 *			resolveFromHeader("X-Tenant-Id", authenticationManagers::get);
	 * </pre>
	 *
	 * {@link HttpServletRequest}
	 * @param resolver A {@link String}-resolving {@link AuthenticationManagerResolver}
	 * @return A header-resolving {@link AuthenticationManagerResolver}
	 */
	public static AuthenticationManagerResolver<HttpServletRequest>
			resolveFromHeader(String headerName, Converter<String, AuthenticationManager> resolver) {

		return new MultiTenantAuthenticationManagerResolver<>
				(request -> request.getHeader(headerName), resolver);
	}
}
