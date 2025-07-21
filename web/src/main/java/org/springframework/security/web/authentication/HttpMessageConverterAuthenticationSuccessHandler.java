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

package org.springframework.security.web.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationSuccessHandler} that writes a JSON response with the redirect
 * URL and an authenticated status similar to:
 *
 * <code>
 *     {
 *         "redirectUrl": "/user/profile",
 *         "authenticated": true
 *     }
 * </code>
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class HttpMessageConverterAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private HttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter();

	private RequestCache requestCache = new HttpSessionRequestCache();

	/**
	 * Sets the {@link GenericHttpMessageConverter} to write to the response. The default
	 * is {@link MappingJackson2HttpMessageConverter}.
	 * @param converter the {@link GenericHttpMessageConverter} to use. Cannot be null.
	 */
	public void setConverter(HttpMessageConverter<Object> converter) {
		Assert.notNull(converter, "converter cannot be null");
		this.converter = converter;
	}

	/**
	 * Sets the {@link RequestCache} to use. The default is
	 * {@link HttpSessionRequestCache}.
	 * @param requestCache the {@link RequestCache} to use. Cannot be null
	 */
	public void setRequestCache(RequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		final SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		final String redirectUrl = (savedRequest != null) ? savedRequest.getRedirectUrl()
				: request.getContextPath() + "/";
		this.requestCache.removeRequest(request, response);
		this.converter.write(new AuthenticationSuccess(redirectUrl), MediaType.APPLICATION_JSON,
				new ServletServerHttpResponse(response));
	}

	/**
	 * A response object used to write the JSON response for successful authentication.
	 *
	 * NOTE: We should be careful about writing {@link Authentication} or
	 * {@link Authentication#getPrincipal()} to the response since it contains
	 * credentials.
	 */
	public static final class AuthenticationSuccess {

		private final String redirectUrl;

		private AuthenticationSuccess(String redirectUrl) {
			this.redirectUrl = redirectUrl;
		}

		public String getRedirectUrl() {
			return this.redirectUrl;
		}

		public boolean isAuthenticated() {
			return true;
		}

	}

}
