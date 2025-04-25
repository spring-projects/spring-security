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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.transport.HttpsRedirectFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Specifies for what requests the application should redirect to HTTPS. When this
 * configurer is added, it redirects all HTTP requests by default to HTTPS.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link HttpsRedirectFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link PortMapper} is used to configure {@link HttpsRedirectFilter}</li>
 * </ul>
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 * @author Josh Cummings
 * @since 6.5
 */
public final class HttpsRedirectConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<HeadersConfigurer<H>, H> {

	private RequestMatcher requestMatcher;

	public HttpsRedirectConfigurer<H> requestMatchers(RequestMatcher... matchers) {
		this.requestMatcher = new OrRequestMatcher(matchers);
		return this;
	}

	@Override
	public void configure(H http) throws Exception {
		HttpsRedirectFilter filter = new HttpsRedirectFilter();
		if (this.requestMatcher != null) {
			filter.setRequestMatcher(this.requestMatcher);
		}
		PortMapper mapper = http.getSharedObject(PortMapper.class);
		if (mapper != null) {
			filter.setPortMapper(mapper);
		}
		http.addFilter(filter);
	}

}
