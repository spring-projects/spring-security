/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

/**
 * Used by the <code>ExceptionTranslationFilter</code> to commence authentication via the
 * {@link BasicAuthenticationFilter}.
 * <p>
 * Once a user agent is authenticated using BASIC authentication, logout requires that the
 * browser be closed or an unauthorized (401) header be sent. The simplest way of
 * achieving the latter is to call the
 * {@link #commence(HttpServletRequest, HttpServletResponse, AuthenticationException)}
 * method below. This will indicate to the browser its credentials are no longer
 * authorized, causing it to prompt the user to login again.
 *
 * @author Ben Alex
 * @author Andrey Litvitski
 */
public class BasicAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

	private @Nullable String realmName;

	private Charset charset = StandardCharsets.UTF_8;

	@Override
	public void afterPropertiesSet() {
		Assert.hasText(this.realmName, "realmName must be specified");
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		String header = "Basic realm=\"" + this.realmName + "\", charset=\"" + this.charset.name() + "\"";
		response.setHeader("WWW-Authenticate", header);
		response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
	}

	public @Nullable String getRealmName() {
		return this.realmName;
	}

	public void setRealmName(String realmName) {
		this.realmName = realmName;
	}

	public void setCharset(Charset charset) {
		this.charset = charset;
	}

	public Charset getCharset() {
		return this.charset;
	}

}
