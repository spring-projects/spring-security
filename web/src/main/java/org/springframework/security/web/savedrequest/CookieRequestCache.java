/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.web.savedrequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;


/**
 * An Implementation of {@code RequestCache} which saves the original request URI in a cookie.
 *
 * @author Zeeshan Adnan
 * @since 5.4
 */
public class CookieRequestCache implements RequestCache {

	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;
	protected final Log logger = LogFactory.getLog(this.getClass());

	private static final String COOKIE_NAME = "REDIRECT_URI";
	private static final int COOKIE_MAX_AGE = -1;

	@Override
	public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
		if (requestMatcher.matches(request)) {
			String redirectUrl = UrlUtils.buildFullRequestUrl(request);
			Cookie savedCookie = new Cookie(COOKIE_NAME, encodeCookie(redirectUrl));
			savedCookie.setMaxAge(COOKIE_MAX_AGE);
			savedCookie.setSecure(request.isSecure());
			savedCookie.setPath(request.getContextPath());
			savedCookie.setHttpOnly(true);

			response.addCookie(savedCookie);
		} else {
			logger.debug("Request not saved as configured RequestMatcher did not match");
		}
	}

	@Override
	public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
		Cookie savedRequestCookie = WebUtils.getCookie(request, COOKIE_NAME);
		if (savedRequestCookie != null) {
			String originalURI = decodeCookie(savedRequestCookie.getValue());
			UriComponents uriComponents = UriComponentsBuilder.fromUriString(originalURI).build();
			DefaultSavedRequest.Builder builder = new DefaultSavedRequest.Builder();

			int port = uriComponents.getPort();
			if (port == -1) {
				if ("https".equalsIgnoreCase(uriComponents.getScheme())) {
					port = 443;
				} else {
					port = 80;
				}
			}
			return builder.setScheme(uriComponents.getScheme())
					.setServerName(uriComponents.getHost())
					.setRequestURI(uriComponents.getPath())
					.setQueryString(uriComponents.getQuery())
					.setServerPort(port)
					.build();
		}
		return null;
	}

	@Override
	public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
		SavedRequest savedRequest = getRequest(request, response);
		if (savedRequest != null) {
			removeRequest(request, response);
			return new SavedRequestAwareWrapper(savedRequest, request);
		}
		return null;
	}

	@Override
	public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
		Cookie removeSavedRequestCookie = new Cookie(COOKIE_NAME, "");
		removeSavedRequestCookie.setSecure(request.isSecure());
		removeSavedRequestCookie.setHttpOnly(true);
		removeSavedRequestCookie.setPath(request.getContextPath());
		removeSavedRequestCookie.setMaxAge(0);
		response.addCookie(removeSavedRequestCookie);
	}

	private static String encodeCookie(String cookieValue) {
		return Base64.getEncoder().encodeToString(cookieValue.getBytes());
	}

	private static String decodeCookie(String encodedCookieValue) {
		return new String(Base64.getDecoder().decode(encodedCookieValue.getBytes()));
	}

	/**
	 * Allows selective use of saved requests for a subset of requests. By default any
	 * request will be cached by the {@code saveRequest} method.
	 * <p>
	 * If set, only matching requests will be cached.
	 *
	 * @param requestMatcher a request matching strategy which defines which requests
	 *                       should be cached.
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher should not be null");
		this.requestMatcher = requestMatcher;
	}

}
