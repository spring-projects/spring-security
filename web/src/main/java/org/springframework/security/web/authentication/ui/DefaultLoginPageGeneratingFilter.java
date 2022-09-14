/*
 * Copyright 2002-2018 the original author or authors.
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
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.HtmlUtils;

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

	private boolean oauth2LoginEnabled;

	private boolean saml2LoginEnabled;

	private String authenticationUrl;

	private String usernameParameter;

	private String passwordParameter;

	private String rememberMeParameter;

	private Map<String, String> oauth2AuthenticationUrlToClientName;

	private Map<String, String> saml2AuthenticationUrlToProviderName;

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = (request) -> Collections.emptyMap();

	public DefaultLoginPageGeneratingFilter() {
	}

	public DefaultLoginPageGeneratingFilter(UsernamePasswordAuthenticationFilter authFilter) {
		this.loginPageUrl = DEFAULT_LOGIN_PAGE_URL;
		this.logoutSuccessUrl = DEFAULT_LOGIN_PAGE_URL + "?logout";
		this.failureUrl = DEFAULT_LOGIN_PAGE_URL + "?" + ERROR_PARAMETER_NAME;
		if (authFilter != null) {
			initAuthFilter(authFilter);
		}
	}

	private void initAuthFilter(UsernamePasswordAuthenticationFilter authFilter) {
		this.formLoginEnabled = true;
		this.usernameParameter = authFilter.getUsernameParameter();
		this.passwordParameter = authFilter.getPasswordParameter();
		if (authFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
			this.rememberMeParameter = ((AbstractRememberMeServices) authFilter.getRememberMeServices()).getParameter();
		}
	}

	/**
	 * Sets a Function used to resolve a Map of the hidden inputs where the key is the
	 * name of the input and the value is the value of the input. Typically this is used
	 * to resolve the CSRF token.
	 * @param resolveHiddenInputs the function to resolve the inputs
	 */
	public void setResolveHiddenInputs(Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	public boolean isEnabled() {
		return this.formLoginEnabled || this.oauth2LoginEnabled || this.saml2LoginEnabled;
	}

	public void setLogoutSuccessUrl(String logoutSuccessUrl) {
		this.logoutSuccessUrl = logoutSuccessUrl;
	}

	public String getLoginPageUrl() {
		return this.loginPageUrl;
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

	public void setOauth2LoginEnabled(boolean oauth2LoginEnabled) {
		this.oauth2LoginEnabled = oauth2LoginEnabled;
	}

	public void setSaml2LoginEnabled(boolean saml2LoginEnabled) {
		this.saml2LoginEnabled = saml2LoginEnabled;
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
	}

	public void setOauth2AuthenticationUrlToClientName(Map<String, String> oauth2AuthenticationUrlToClientName) {
		this.oauth2AuthenticationUrlToClientName = oauth2AuthenticationUrlToClientName;
	}

	public void setSaml2AuthenticationUrlToProviderName(Map<String, String> saml2AuthenticationUrlToProviderName) {
		this.saml2AuthenticationUrlToProviderName = saml2AuthenticationUrlToProviderName;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		boolean loginError = isErrorPage(request);
		boolean logoutSuccess = isLogoutSuccess(request);
		if (isLoginUrlRequest(request) || loginError || logoutSuccess) {
			String loginPageHtml = generateLoginPageHtml(request, loginError, logoutSuccess);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(loginPageHtml);
			return;
		}
		chain.doFilter(request, response);
	}

	private String generateLoginPageHtml(HttpServletRequest request, boolean loginError, boolean logoutSuccess) {
		String errorMsg = "Invalid credentials";
		if (loginError) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				AuthenticationException ex = (AuthenticationException) session
						.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
				errorMsg = (ex != null) ? ex.getMessage() : "Invalid credentials";
			}
		}
		String contextPath = request.getContextPath();
		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>\n");
		sb.append("<html lang=\"en\">\n");
		sb.append("  <head>\n");
		sb.append("    <meta charset=\"utf-8\">\n");
		sb.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n");
		sb.append("    <meta name=\"description\" content=\"\">\n");
		sb.append("    <meta name=\"author\" content=\"\">\n");
		sb.append("    <title>Please sign in</title>\n");
		sb.append("    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" "
				+ "rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n");
		sb.append("    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" "
				+ "rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n");
		sb.append("  </head>\n");
		sb.append("  <body>\n");
		sb.append("     <div class=\"container\">\n");
		if (this.formLoginEnabled) {
			sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath
					+ this.authenticationUrl + "\">\n");
			sb.append("        <h2 class=\"form-signin-heading\">Please sign in</h2>\n");
			sb.append(createError(loginError, errorMsg) + createLogoutSuccess(logoutSuccess) + "        <p>\n");
			sb.append("          <label for=\"username\" class=\"sr-only\">Username</label>\n");
			sb.append("          <input type=\"text\" id=\"username\" name=\"" + this.usernameParameter
					+ "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n");
			sb.append("        </p>\n");
			sb.append("        <p>\n");
			sb.append("          <label for=\"password\" class=\"sr-only\">Password</label>\n");
			sb.append("          <input type=\"password\" id=\"password\" name=\"" + this.passwordParameter
					+ "\" class=\"form-control\" placeholder=\"Password\" required>\n");
			sb.append("        </p>\n");
			sb.append(createRememberMe(this.rememberMeParameter) + renderHiddenInputs(request));
			sb.append("        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n");
			sb.append("      </form>\n");
		}
		if (this.oauth2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with OAuth 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> clientAuthenticationUrlToClientName : this.oauth2AuthenticationUrlToClientName
					.entrySet()) {
				sb.append(" <tr><td>");
				String url = clientAuthenticationUrlToClientName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String clientName = HtmlUtils.htmlEscape(clientAuthenticationUrlToClientName.getValue());
				sb.append(clientName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table>\n");
		}
		if (this.saml2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with SAML 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> relyingPartyUrlToName : this.saml2AuthenticationUrlToProviderName
					.entrySet()) {
				sb.append(" <tr><td>");
				String url = relyingPartyUrlToName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String partyName = HtmlUtils.htmlEscape(relyingPartyUrlToName.getValue());
				sb.append(partyName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table>\n");
		}
		sb.append("</div>\n");
		sb.append("</body></html>");
		return sb.toString();
	}

	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			sb.append("<input name=\"");
			sb.append(input.getKey());
			sb.append("\" type=\"hidden\" value=\"");
			sb.append(input.getValue());
			sb.append("\" />\n");
		}
		return sb.toString();
	}

	private String createRememberMe(String paramName) {
		if (paramName == null) {
			return "";
		}
		return "<p><input type='checkbox' name='" + paramName + "'/> Remember me on this computer.</p>\n";
	}

	private boolean isLogoutSuccess(HttpServletRequest request) {
		return this.logoutSuccessUrl != null && matches(request, this.logoutSuccessUrl);
	}

	private boolean isLoginUrlRequest(HttpServletRequest request) {
		return matches(request, this.loginPageUrl);
	}

	private boolean isErrorPage(HttpServletRequest request) {
		return matches(request, this.failureUrl);
	}

	private static String createError(boolean isError, String message) {
		if (!isError) {
			return "";
		}
		return "<div class=\"alert alert-danger\" role=\"alert\">" + HtmlUtils.htmlEscape(message) + "</div>";
	}

	private static String createLogoutSuccess(boolean isLogoutSuccess) {
		if (!isLogoutSuccess) {
			return "";
		}
		return "<div class=\"alert alert-success\" role=\"alert\">You have been signed out</div>";
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
