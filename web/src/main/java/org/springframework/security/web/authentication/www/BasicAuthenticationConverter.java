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
package org.springframework.security.web.authentication.www;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Converts from a HttpServletRequest to
 * {@link UsernamePasswordAuthenticationToken} that can be authenticated. Null
 * authentication possible if there was no Authorization header with Basic
 * authentication scheme.
 *
 * @author Sergey Bespalov
 * @since 5.2.0
 */
public class BasicAuthenticationConverter implements AuthenticationConverter {

	public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	private String credentialsCharset = StandardCharsets.UTF_8.name();

	public BasicAuthenticationConverter() {
		this(new WebAuthenticationDetailsSource());
	}

	public BasicAuthenticationConverter(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public String getCredentialsCharset() {
		return credentialsCharset;
	}

	public void setCredentialsCharset(String credentialsCharset) {
		this.credentialsCharset = credentialsCharset;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	@Override
	public UsernamePasswordAuthenticationToken convert(HttpServletRequest request) {
		String header = request.getHeader(AUTHORIZATION);
		if (header == null) {
			return null;
		}

		header = header.trim();
		if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
			return null;
		}

		byte[] base64Token = header.substring(6).getBytes();
		byte[] decoded;
		try {
			decoded = Base64.getDecoder().decode(base64Token);
		} catch (IllegalArgumentException e) {
			throw new BadCredentialsException("Failed to decode basic authentication token");
		}

		String token;
		try {
			token = new String(decoded, getCredentialsCharset(request));
		} catch (UnsupportedEncodingException e) {
			throw new InternalAuthenticationServiceException(e.getMessage(), e);
		}

		String[] tokens = token.split(":");
		if (tokens.length != 2) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}

		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(tokens[0],
				tokens[1]);
		authentication.setDetails(authenticationDetailsSource.buildDetails(request));

		return authentication;
	}

	protected String getCredentialsCharset(HttpServletRequest request) {
		return getCredentialsCharset();
	}

}
