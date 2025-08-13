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

package org.springframework.security.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;

public final class AuthorizationRequestingAccessDeniedHandler implements AccessDeniedHandler {

	private final List<AuthorizationEntryPoint> entries;

	private final AccessDeniedHandler delegate = new AccessDeniedHandlerImpl();

	public AuthorizationRequestingAccessDeniedHandler(List<AuthorizationEntryPoint> entries) {
		this.entries = new ArrayList<>(entries);
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException access)
			throws IOException, ServletException {
		AuthorizationRequest authorizationRequest = authorizationRequest(access);
		if (authorizationRequest == null) {
			this.delegate.handle(request, response, access);
			return;
		}
		for (AuthorizationEntryPoint entry : this.entries) {
			if (!entry.grantableAuthorities(authorizationRequest).isEmpty()) {
				AuthenticationException iae = new InsufficientAuthenticationException("access denied", access);
				entry.commence(request, response, iae);
				return;
			}
		}
		this.delegate.handle(request, response, access);
	}

	private AuthorizationRequest authorizationRequest(AccessDeniedException access) {
		if (access instanceof AuthorizationRequest request) {
			return request;
		}
		if (!(access instanceof AuthorizationDeniedException denied)) {
			return null;
		}
		if (!(denied.getAuthorizationResult() instanceof AuthorizationRequest request)) {
			return null;
		}
		return request;
	}

}
