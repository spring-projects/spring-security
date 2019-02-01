/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.authentication.supply;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.AuthenticationType;

/**
 * This class decorates a underlying {@link AuthenticationSupplier} with common
 * logic needed for {@link AbstractAuthenticationToken}.
 *
 * @author Sergey Bespalov
 *
 * @param <T>
 */
public class AuthenticationTokenSupplier<T extends AbstractAuthenticationToken> implements AuthenticationSupplier<T> {

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private final AuthenticationSupplier<T> delegate;

	public AuthenticationTokenSupplier(AuthenticationSupplier<T> delegate) {
		super();
		this.delegate = delegate;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	@Override
	public T supply(HttpServletRequest request) throws AuthenticationException {
		T authentication = delegate.supply(request);

		Object authenticationDetails = getAuthenticationDetailsSource().buildDetails(request);
		authentication.setDetails(authenticationDetails);

		return authentication;
	}

	public AuthenticationType getAuthenticationType() {
		return delegate.getAuthenticationType();
	}

	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		delegate.commence(request, response, authException);
	}

}
