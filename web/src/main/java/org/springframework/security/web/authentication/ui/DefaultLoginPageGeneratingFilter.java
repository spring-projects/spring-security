/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication.ui;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.GenericFilterBean;

/**
 * For internal use with namespace configuration in the case where a user doesn't
 * configure a login page. The configuration code will insert this filter in the chain
 * instead.
 *
 * Will only work if a redirect is used to the login page.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class DefaultLoginPageGeneratingFilter extends GenericFilterBean {
	public static final String DEFAULT_LOGIN_PAGE_URL = "/login";
	public static final String ERROR_PARAMETER_NAME = "error";
	private String loginPageUrl;
	private String logoutSuccessUrl;
	private String failureUrl;
	private boolean formLoginEnabled;
	private boolean openIdEnabled;
	private String authenticationUrl;
	private String usernameParameter;
	private String passwordParameter;
	private String rememberMeParameter;
	private String openIDauthenticationUrl;
	private String openIDusernameParameter;
	private String openIDrememberMeParameter;

	public DefaultLoginPageGeneratingFilter() {
	}

	public DefaultLoginPageGeneratingFilter(AbstractAuthenticationProcessingFilter filter) {
		if (filter instanceof UsernamePasswordAuthenticationFilter) {
			init((UsernamePasswordAuthenticationFilter) filter, null);
		}
		else {
			init(null, filter);
		}
	}

	public DefaultLoginPageGeneratingFilter(
			UsernamePasswordAuthenticationFilter authFilter,
			AbstractAuthenticationProcessingFilter openIDFilter) {
		init(authFilter, openIDFilter);
	}

	private void init(UsernamePasswordAuthenticationFilter authFilter,
			AbstractAuthenticationProcessingFilter openIDFilter) {
		this.loginPageUrl = DEFAULT_LOGIN_PAGE_URL;
		this.logoutSuccessUrl = DEFAULT_LOGIN_PAGE_URL + "?logout";
		this.failureUrl = DEFAULT_LOGIN_PAGE_URL + "?" + ERROR_PARAMETER_NAME;
		if (authFilter != null) {
			formLoginEnabled = true;
			usernameParameter = authFilter.getUsernameParameter();
			passwordParameter = authFilter.getPasswordParameter();

			if (authFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
				rememberMeParameter = ((AbstractRememberMeServices) authFilter
						.getRememberMeServices()).getParameter();
			}
		}

		if (openIDFilter != null) {
			openIdEnabled = true;
			openIDusernameParameter = "openid_identifier";

			if (openIDFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
				openIDrememberMeParameter = ((AbstractRememberMeServices) openIDFilter
						.getRememberMeServices()).getParameter();
			}
		}
	}

	public boolean isEnabled() {
		return formLoginEnabled || openIdEnabled;
	}

	public void setLogoutSuccessUrl(String logoutSuccessUrl) {
		this.logoutSuccessUrl = logoutSuccessUrl;
	}

	public String getLoginPageUrl() {
		return loginPageUrl;
	}

	public void setLoginPageUrl(String loginPageUrl) {
		this.loginPageUrl = loginPageUrl;
	}

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}

	public void setFormLoginEnabled(boolean formLoginEnabled) {
		this.formLoginEnabled = formLoginEnabled;
	}

	public void setOpenIdEnabled(boolean openIdEnabled) {
		this.openIdEnabled = openIdEnabled;
	}

	public void setAuthenticationUrl(String authenticationUrl) {
		this.authenticationUrl = authenticationUrl;
	}

	public void setUsernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
	}

	public void setPasswordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

	public void setRememberMeParameter(String rememberMeParameter) {
		this.rememberMeParameter = rememberMeParameter;
		this.openIDrememberMeParameter = rememberMeParameter;
	}

	public void setOpenIDauthenticationUrl(String openIDauthenticationUrl) {
		this.openIDauthenticationUrl = openIDauthenticationUrl;
	}

	public void setOpenIDusernameParameter(String openIDusernameParameter) {
		this.openIDusernameParameter = openIDusernameParameter;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		boolean loginError = isErrorPage(request);
		boolean logoutSuccess = isLogoutSuccess(request);
		if (isLoginUrlRequest(request) || loginError || logoutSuccess) {
			String loginPageHtml = generateLoginPageHtml(request, loginError,
					logoutSuccess);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(loginPageHtml.length());
			response.getWriter().write(loginPageHtml);

			return;
		}

		chain.doFilter(request, response);
	}

	private String generateLoginPageHtml(HttpServletRequest request, boolean loginError,
			boolean logoutSuccess) {
		String errorMsg = "none";

		if (loginError) {
			HttpSession session = request.getSession(false);

			if (session != null) {
				AuthenticationException ex = (AuthenticationException) session
						.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
				errorMsg = ex != null ? ex.getMessage() : "none";
			}
		}

		StringBuilder sb = new StringBuilder();

		sb.append("<html><head><title>Login Page</title></head>");

		if (formLoginEnabled) {
			sb.append("<body onload='document.f.").append(usernameParameter)
					.append(".focus();'>\n");
		}

		if (loginError) {
			sb.append("<p><font color='red'>Your login attempt was not successful, try again.<br/><br/>Reason: ");
			sb.append(errorMsg);
			sb.append("</font></p>");
		}

		if (logoutSuccess) {
			sb.append("<p><font color='green'>You have been logged out</font></p>");
		}

		if (formLoginEnabled) {
			sb.append("<h3>Login with Username and Password</h3>");
			sb.append("<form name='f' action='").append(request.getContextPath())
					.append(authenticationUrl).append("' method='POST'>\n");
			sb.append("<table>\n");
			sb.append("	<tr><td>User:</td><td><input type='text' name='");
			sb.append(usernameParameter).append("' value='").append("'></td></tr>\n");
			sb.append("	<tr><td>Password:</td><td><input type='password' name='")
					.append(passwordParameter).append("'/></td></tr>\n");

			if (rememberMeParameter != null) {
				sb.append("	<tr><td><input type='checkbox' name='")
						.append(rememberMeParameter)
						.append("'/></td><td>Remember me on this computer.</td></tr>\n");
			}

			sb.append("	<tr><td colspan='2'><input name=\"submit\" type=\"submit\" value=\"Login\"/></td></tr>\n");
			renderHiddenInputs(sb, request);
			sb.append("</table>\n");
			sb.append("</form>");
		}

		if (openIdEnabled) {
			sb.append("<h3>Login with OpenID Identity</h3>");
			sb.append("<form name='oidf' action='").append(request.getContextPath())
					.append(openIDauthenticationUrl).append("' method='POST'>\n");
			sb.append("<table>\n");
			sb.append("	<tr><td>Identity:</td><td><input type='text' size='30' name='");
			sb.append(openIDusernameParameter).append("'/></td></tr>\n");

			if (openIDrememberMeParameter != null) {
				sb.append("	<tr><td><input type='checkbox' name='")
						.append(openIDrememberMeParameter)
						.append("'></td><td>Remember me on this computer.</td></tr>\n");
			}

			sb.append("	<tr><td colspan='2'><input name=\"submit\" type=\"submit\" value=\"Login\"/></td></tr>\n");
			sb.append("</table>\n");
			renderHiddenInputs(sb, request);
			sb.append("</form>");
		}

		sb.append("</body></html>");

		return sb.toString();
	}

	private void renderHiddenInputs(StringBuilder sb, HttpServletRequest request) {
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

		if (token != null) {
			sb.append("	<input name=\"" + token.getParameterName()
					+ "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n");
		}
	}

	private boolean isLogoutSuccess(HttpServletRequest request) {
		return logoutSuccessUrl != null && matches(request, logoutSuccessUrl);
	}

	private boolean isLoginUrlRequest(HttpServletRequest request) {
		return matches(request, loginPageUrl);
	}

	private boolean isErrorPage(HttpServletRequest request) {
		return matches(request, failureUrl);
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
