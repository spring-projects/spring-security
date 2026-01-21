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

package org.springframework.security.kerberos.web.authentication;

import java.io.IOException;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Sends back a request for a Negotiate Authentication to the browser.
 *
 * <p>
 * With optional configured <code>forwardUrl</code> it is possible to use form login as
 * fallback authentication.
 * </p>
 *
 * <p>
 * This approach enables security configuration to use SPNEGO in combination with login
 * form as fallback for clients that do not support this kind of authentication. Set
 * Response Code 401 - unauthorized and forward to login page. A useful scenario might be
 * an environment where windows domain is present but it is required to access the
 * application also from non domain client devices. One could use a combination with form
 * based LDAP login.
 * </p>
 *
 * <p>
 * See <code>spnego-with-form-login.xml</code> in spring-security-kerberos-sample for
 * details
 * </p>
 *
 * @author Mike Wiesner
 * @author Andre Schaefer, Namics AG
 * @since 1.0
 * @see SpnegoAuthenticationProcessingFilter
 */
public class SpnegoEntryPoint implements AuthenticationEntryPoint {

	private static final Log LOG = LogFactory.getLog(SpnegoEntryPoint.class);

	private final @Nullable String forwardUrl;

	private final @Nullable HttpMethod forwardMethod;

	private final boolean forward;

	/**
	 * Instantiates a new spnego entry point. Using this constructor the EntryPoint will
	 * Sends back a request for a Negotiate Authentication to the browser without
	 * providing a fallback mechanism for login, Use constructor with forwardUrl to
	 * provide form based login.
	 */
	public SpnegoEntryPoint() {
		this(null);
	}

	/**
	 * Instantiates a new spnego entry point. This constructor enables security
	 * configuration to use SPNEGO in combination with a fallback page (login form, custom
	 * 401 page ...). The forward method will be the same as the original request.
	 * @param forwardUrl URL where the login page can be found. Should be relative to the
	 * web-app context path (include a leading {@code /}) and can't be absolute URL.
	 */
	public SpnegoEntryPoint(@Nullable String forwardUrl) {
		this(forwardUrl, null);
	}

	/**
	 * Instantiates a new spnego entry point. This constructor enables security
	 * configuration to use SPNEGO in combination with a fallback page (login form, custom
	 * 401 page ...). The forward URL will be accessed via provided HTTP method.
	 * @param forwardUrl URL where the login page can be found. Should be relative to the
	 * web-app context path (include a leading {@code /}) and can't be absolute URL.
	 * @param forwardMethod HTTP method to use when accessing the forward URL
	 */
	public SpnegoEntryPoint(@Nullable String forwardUrl, @Nullable HttpMethod forwardMethod) {
		if (StringUtils.hasText(forwardUrl)) {
			Assert.isTrue(UrlUtils.isValidRedirectUrl(forwardUrl), "Forward url specified must be a valid forward URL");
			Assert.isTrue(!UrlUtils.isAbsoluteUrl(forwardUrl), "Forward url specified must not be absolute");

			this.forwardUrl = forwardUrl;
			this.forwardMethod = forwardMethod;
			this.forward = true;
		}
		else {
			this.forwardUrl = null;
			this.forwardMethod = null;
			this.forward = false;
		}
	}

	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
			throws IOException, ServletException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Add header WWW-Authenticate:Negotiate to " + request.getRequestURL() + ", forward: "
					+ (this.forward ? this.forwardUrl : "no"));
		}
		response.addHeader("WWW-Authenticate", "Negotiate");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

		if (this.forward) {
			RequestDispatcher dispatcher = request.getRequestDispatcher(this.forwardUrl);
			HttpMethod method = this.forwardMethod;
			HttpServletRequest fwdRequest = (method != null) ? new HttpServletRequestWrapper(request) {
				@Override
				public String getMethod() {
					return method.name();
				}
			} : request;
			dispatcher.forward(fwdRequest, response);
		}
		else {
			response.flushBuffer();
		}
	}

}
