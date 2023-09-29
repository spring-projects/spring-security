/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.messaging.web.socket.server;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.DeferredCsrfToken;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

/**
 * Loads a CsrfToken from the HttpServletRequest and HttpServletResponse to populate the
 * WebSocket attributes. This is used as the expected CsrfToken when validating connection
 * requests to ensure only the same origin connects.
 *
 * @author Rob Winch
 * @author Steve Riesenberg
 * @since 4.0
 */
public final class CsrfTokenHandshakeInterceptor implements HandshakeInterceptor {

	@Override
	public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler,
			Map<String, Object> attributes) {
		HttpServletRequest httpRequest = ((ServletServerHttpRequest) request).getServletRequest();
		DeferredCsrfToken deferredCsrfToken = (DeferredCsrfToken) httpRequest
			.getAttribute(DeferredCsrfToken.class.getName());
		if (deferredCsrfToken == null) {
			return true;
		}
		CsrfToken csrfToken = deferredCsrfToken.get();
		// Ensure the values of the CsrfToken are copied into a new token so the old token
		// is available for garbage collection.
		// This is required because the original token could hold a reference to the
		// HttpServletRequest/Response of the handshake request.
		CsrfToken resolvedCsrfToken = new DefaultCsrfToken(csrfToken.getHeaderName(), csrfToken.getParameterName(),
				csrfToken.getToken());
		attributes.put(CsrfToken.class.getName(), resolvedCsrfToken);
		return true;
	}

	@Override
	public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler,
			Exception exception) {
	}

}
