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

package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * Adds request cache for Spring Security. Specifically this ensures that requests that
 * are saved (i.e. after authentication is required) are later replayed. All properties
 * have reasonable defaults, so no additional configuration is required other than
 * applying this {@link org.springframework.security.config.annotation.SecurityConfigurer}
 * .
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link RequestCacheAwareFilter}</li>
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
 * <li>If no explicit {@link RequestCache}, is provided a {@link RequestCache} shared
 * object is used to replay the request after authentication is successful</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Ngoc Nhan
 * @since 3.2
 * @see RequestCache
 */
public final class RequestCacheConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<RequestCacheConfigurer<H>, H> {

	public RequestCacheConfigurer() {
	}

	/**
	 * Allows explicit configuration of the {@link RequestCache} to be used. Defaults to
	 * try finding a {@link RequestCache} as a shared object. Then falls back to a
	 * {@link HttpSessionRequestCache}.
	 * @param requestCache the explicit {@link RequestCache} to use
	 * @return the {@link RequestCacheConfigurer} for further customization
	 */
	public RequestCacheConfigurer<H> requestCache(RequestCache requestCache) {
		getBuilder().setSharedObject(RequestCache.class, requestCache);
		return this;
	}

	@Override
	public H disable() {
		getBuilder().setSharedObject(RequestCache.class, new NullRequestCache());
		return super.disable();
	}

	@Override
	public void init(H http) {
		http.setSharedObject(RequestCache.class, getRequestCache(http));
	}

	@Override
	public void configure(H http) {
		RequestCache requestCache = getRequestCache(http);
		RequestCacheAwareFilter requestCacheFilter = new RequestCacheAwareFilter(requestCache);
		requestCacheFilter = postProcess(requestCacheFilter);
		http.addFilter(requestCacheFilter);
	}

	/**
	 * Gets the {@link RequestCache} to use. If one is defined using
	 * {@link #requestCache(org.springframework.security.web.savedrequest.RequestCache)},
	 * then it is used. Otherwise, an attempt to find a {@link RequestCache} shared object
	 * is made. If that fails, an {@link HttpSessionRequestCache} is used
	 * @param http the {@link HttpSecurity} to attempt to fined the shared object
	 * @return the {@link RequestCache} to use
	 */
	private RequestCache getRequestCache(H http) {
		RequestCache result = http.getSharedObject(RequestCache.class);
		if (result != null) {
			return result;
		}
		result = getBeanOrNull(RequestCache.class);
		if (result != null) {
			return result;
		}
		HttpSessionRequestCache defaultCache = new HttpSessionRequestCache();
		defaultCache.setRequestMatcher(createDefaultSavedRequestMatcher(http));
		return defaultCache;
	}

	private <T> T getBeanOrNull(Class<T> type) {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		if (context == null) {
			return null;
		}

		return context.getBeanProvider(type).getIfUnique();
	}

	@SuppressWarnings("unchecked")
	private RequestMatcher createDefaultSavedRequestMatcher(H http) {
		RequestMatcher notFavIcon = new NegatedRequestMatcher(new AntPathRequestMatcher("/**/favicon.*"));
		RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
		boolean isCsrfEnabled = http.getConfigurer(CsrfConfigurer.class) != null;
		List<RequestMatcher> matchers = new ArrayList<>();
		if (isCsrfEnabled) {
			RequestMatcher getRequests = new AntPathRequestMatcher("/**", "GET");
			matchers.add(0, getRequests);
		}
		matchers.add(notFavIcon);
		matchers.add(notMatchingMediaType(http, MediaType.APPLICATION_JSON));
		matchers.add(notXRequestedWith);
		matchers.add(notMatchingMediaType(http, MediaType.MULTIPART_FORM_DATA));
		matchers.add(notMatchingMediaType(http, MediaType.TEXT_EVENT_STREAM));
		return new AndRequestMatcher(matchers);
	}

	private RequestMatcher notMatchingMediaType(H http, MediaType mediaType) {
		ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}
		MediaTypeRequestMatcher mediaRequest = new MediaTypeRequestMatcher(contentNegotiationStrategy, mediaType);
		mediaRequest.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		return new NegatedRequestMatcher(mediaRequest);
	}

}
