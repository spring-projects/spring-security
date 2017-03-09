/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.authentication.ui;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * @author Joe Grandja
 */
public abstract class AbstractLoginPageGeneratingFilter extends GenericFilterBean {
	public static final String DEFAULT_LOGIN_PAGE_URL = "/login";
	public static final String LOGOUT_PARAMETER_NAME = "logout";
	public static final String ERROR_PARAMETER_NAME = "error";
	private String loginPageUrl;
	private String logoutSuccessUrl;
	private String failureUrl;
	private String authenticationUrl;
	private boolean loginEnabled;


	protected AbstractLoginPageGeneratingFilter() {
		this.loginPageUrl = DEFAULT_LOGIN_PAGE_URL;
		this.logoutSuccessUrl = DEFAULT_LOGIN_PAGE_URL + "?" + LOGOUT_PARAMETER_NAME;
		this.failureUrl = DEFAULT_LOGIN_PAGE_URL + "?" + ERROR_PARAMETER_NAME;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		boolean loginError = this.isLoginError(request);
		boolean logoutSuccess = this.isLogoutSuccess(request);
		if (this.isLoginRequest(request) || loginError || logoutSuccess) {
			String loginPageHtml = this.generateLoginPageHtml(
					request, loginError, logoutSuccess);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(loginPageHtml.length());
			response.getWriter().write(loginPageHtml);

			return;
		}

		chain.doFilter(request, response);
	}

	public abstract String generateLoginPageHtml(HttpServletRequest request,
													boolean loginError, boolean logoutSuccess);

	public String getLoginPageUrl() {
		return this.loginPageUrl;
	}

	public void setLoginPageUrl(String loginPageUrl) {
		this.loginPageUrl = loginPageUrl;
	}

	public void setLogoutSuccessUrl(String logoutSuccessUrl) {
		this.logoutSuccessUrl = logoutSuccessUrl;
	}

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}

	public String getAuthenticationUrl() {
		return this.authenticationUrl;
	}

	public void setAuthenticationUrl(String authenticationUrl) {
		this.authenticationUrl = authenticationUrl;
	}

	public boolean isLoginEnabled() {
		return this.loginEnabled;
	}

	public void setLoginEnabled(boolean loginEnabled) {
		this.loginEnabled = loginEnabled;
	}

	protected String resolveErrorMessage(HttpServletRequest request) {
		String errorMsg = "none";
		HttpSession session = request.getSession(false);
		if (session != null) {
			AuthenticationException ex = (AuthenticationException) session
					.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
			if (ex != null) {
				return ex.getMessage();
			}
		}

		return errorMsg;
	}

	protected void renderHiddenInputs(StringBuilder sb, HttpServletRequest request) {
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

		if (token != null) {
			sb.append("	<input name=\"" + token.getParameterName()
					+ "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n");
		}
	}

	protected boolean isLoginRequest(HttpServletRequest request) {
		return this.matches(request, this.loginPageUrl);
	}

	protected boolean isLogoutSuccess(HttpServletRequest request) {
		return this.matches(request, this.logoutSuccessUrl);
	}

	protected boolean isLoginError(HttpServletRequest request) {
		return this.matches(request, this.failureUrl);
	}

	private boolean matches(HttpServletRequest request, String url) {
		if (!"GET".equals(request.getMethod()) || url == null) {
			return false;
		}
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}

		if (request.getQueryString() != null) {
			uri += "?" + request.getQueryString();
		}

		if ("".equals(request.getContextPath())) {
			return uri.equals(url);
		}

		return uri.equals(request.getContextPath() + url);
	}
}
