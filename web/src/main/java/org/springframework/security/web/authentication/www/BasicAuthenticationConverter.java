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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Converts from a HttpServletRequest to {@link UsernamePasswordAuthenticationToken} that
 * can be authenticated. Null authentication possible if there was no Authorization header
 * with Basic authentication scheme.
 *
 * @author Sergey Bespalov
 * @since 5.2.0
 */
public class BasicAuthenticationConverter implements AuthenticationConverter {

	public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	private Charset credentialsCharset = StandardCharsets.UTF_8;

	public BasicAuthenticationConverter() {
		this(new WebAuthenticationDetailsSource());
	}

	public BasicAuthenticationConverter(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public Charset getCredentialsCharset() {
		return this.credentialsCharset;
	}

	public void setCredentialsCharset(Charset credentialsCharset) {
		this.credentialsCharset = credentialsCharset;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return this.authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	@Override
	public UsernamePasswordAuthenticationToken convert(HttpServletRequest request) {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null) {
			return null;
		}

		header = header.trim();
		if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
			return null;
		}

		if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
			throw new BadCredentialsException("Empty basic authentication token");
		}

		byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
		byte[] decoded;
		try {
			decoded = Base64.getDecoder().decode(base64Token);
		}
		catch (IllegalArgumentException ex) {
			throw new BadCredentialsException("Failed to decode basic authentication token");
		}

		String token = new String(decoded, getCredentialsCharset(request));

		int delim = token.indexOf(":");

		if (delim == -1) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(token.substring(0, delim),
				token.substring(delim + 1));
		result.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return result;
	}

	protected Charset getCredentialsCharset(HttpServletRequest request) {
		return getCredentialsCharset();
	}

}
