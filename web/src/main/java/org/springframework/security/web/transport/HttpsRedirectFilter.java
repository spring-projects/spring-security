/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.transport;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Redirects any non-HTTPS request to its HTTPS equivalent.
 *
 * <p>
 * Can be configured to use a {@link RequestMatcher} to narrow which requests get
 * redirected.
 *
 * <p>
 * Can also be configured for custom ports using {@link PortMapper}.
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class HttpsRedirectFilter extends OncePerRequestFilter {

	private PortMapper portMapper = new PortMapperImpl();

	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		if (!isInsecure(request)) {
			chain.doFilter(request, response);
			return;
		}
		if (!this.requestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}
		String redirectUri = createRedirectUri(request);
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
	}

	/**
	 * Use this {@link PortMapper} for mapping custom ports
	 * @param portMapper the {@link PortMapper} to use
	 */
	public void setPortMapper(PortMapper portMapper) {
		Assert.notNull(portMapper, "portMapper cannot be null");
		this.portMapper = portMapper;
	}

	/**
	 * Use this {@link RequestMatcher} to narrow which requests are redirected to HTTPS.
	 *
	 * The filter already first checks for HTTPS in the uri scheme, so it is not necessary
	 * to include that check in this matcher.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	private boolean isInsecure(HttpServletRequest request) {
		return !"https".equals(request.getScheme());
	}

	private String createRedirectUri(HttpServletRequest request) {
		String url = UrlUtils.buildFullRequestUrl(request);
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
		UriComponents components = builder.build();
		int port = components.getPort();
		if (port > 0) {
			Integer httpsPort = this.portMapper.lookupHttpsPort(port);
			Assert.state(httpsPort != null, () -> "HTTP Port '" + port + "' does not have a corresponding HTTPS Port");
			builder.port(httpsPort);
		}
		return builder.scheme("https").toUriString();
	}

}
