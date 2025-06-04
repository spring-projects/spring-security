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

package org.springframework.security.oauth2.server.resource.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;

public final class DPoPAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) {
		Map<String, String> parameters = new LinkedHashMap<>();
		if (authenticationException instanceof OAuth2AuthenticationException oauth2AuthenticationException) {
			OAuth2Error error = oauth2AuthenticationException.getError();
			parameters.put(OAuth2ParameterNames.ERROR, error.getErrorCode());
			if (StringUtils.hasText(error.getDescription())) {
				parameters.put(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
			}
			if (StringUtils.hasText(error.getUri())) {
				parameters.put(OAuth2ParameterNames.ERROR_URI, error.getUri());
			}
		}
		parameters.put("algs",
				JwsAlgorithms.RS256 + " " + JwsAlgorithms.RS384 + " " + JwsAlgorithms.RS512 + " "
						+ JwsAlgorithms.PS256 + " " + JwsAlgorithms.PS384 + " " + JwsAlgorithms.PS512 + " "
						+ JwsAlgorithms.ES256 + " " + JwsAlgorithms.ES384 + " " + JwsAlgorithms.ES512);
		String wwwAuthenticate = toWWWAuthenticateHeader(parameters);
		response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
	}

	private String toWWWAuthenticateHeader(Map<String, String> parameters) {
		StringBuilder wwwAuthenticate = new StringBuilder();
		wwwAuthenticate.append(OAuth2AccessToken.TokenType.DPOP.getValue());
		if (!parameters.isEmpty()) {
			wwwAuthenticate.append(" ");
			int i = 0;
			for (Map.Entry<String, String> entry : parameters.entrySet()) {
				wwwAuthenticate.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\"");
				if (i++ != parameters.size() - 1) {
					wwwAuthenticate.append(", ");
				}
			}
		}
		return wwwAuthenticate.toString();
	}
}
