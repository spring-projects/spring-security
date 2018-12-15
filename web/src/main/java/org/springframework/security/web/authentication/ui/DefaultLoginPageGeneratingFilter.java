/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.web.authentication.ui;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

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
	private boolean oauth2LoginEnabled;
	private String authenticationUrl;
	private String usernameParameter;
	private String passwordParameter;
	private String rememberMeParameter;
	private String openIDauthenticationUrl;
	private String openIDusernameParameter;
	private String openIDrememberMeParameter;
	private Map<String, String> oauth2AuthenticationUrlToClientName;
	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = request -> Collections
		.emptyMap();


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

	/**
	 * Sets a Function used to resolve a Map of the hidden inputs where the key is the
	 * name of the input and the value is the value of the input. Typically this is used
	 * to resolve the CSRF token.
	 * @param resolveHiddenInputs the function to resolve the inputs
	 */
	public void setResolveHiddenInputs(
		Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	public boolean isEnabled() {
		return formLoginEnabled || openIdEnabled || oauth2LoginEnabled;
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

	public void setOauth2LoginEnabled(boolean oauth2LoginEnabled) {
		this.oauth2LoginEnabled = oauth2LoginEnabled;
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

	public void setOauth2AuthenticationUrlToClientName(Map<String, String> oauth2AuthenticationUrlToClientName) {
		this.oauth2AuthenticationUrlToClientName = oauth2AuthenticationUrlToClientName;
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
			response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(loginPageHtml);

			return;
		}

		chain.doFilter(request, response);
	}

	private String generateLoginPageHtml(HttpServletRequest request, boolean loginError,
			boolean logoutSuccess) {
		String errorMsg = "Invalid credentials";

		if (loginError) {
			HttpSession session = request.getSession(false);

			if (session != null) {
				AuthenticationException ex = (AuthenticationException) session
						.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
				errorMsg = ex != null ? ex.getMessage() : "Invalid credentials";
			}
		}

		StringBuilder sb = new StringBuilder();

		sb.append("<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n"
				+ "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "     <div class=\"container\">\n");

		String contextPath = request.getContextPath();
		if (this.formLoginEnabled) {
			sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath + this.authenticationUrl + "\">\n"
					+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
					+ createError(loginError, errorMsg)
					+ createLogoutSuccess(logoutSuccess)
					+ "        <p>\n"
					+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
					+ "          <input type=\"text\" id=\"username\" name=\"" + this.usernameParameter + "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
					+ "        </p>\n"
					+ "        <p>\n"
					+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
					+ "          <input type=\"password\" id=\"password\" name=\"" + this.passwordParameter + "\" class=\"form-control\" placeholder=\"Password\" required>\n"
					+ "        </p>\n"
					+ createRememberMe(this.rememberMeParameter)
					+ renderHiddenInputs(request)
					+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
					+ "      </form>\n");
		}

		if (openIdEnabled) {
			sb.append("      <form name=\"oidf\" class=\"form-signin\" method=\"post\" action=\"" + contextPath + this.openIDauthenticationUrl + "\">\n"
					+ "        <h2 class=\"form-signin-heading\">Login with OpenID Identity</h2>\n"
					+ createError(loginError, errorMsg)
					+ createLogoutSuccess(logoutSuccess)
					+ "        <p>\n"
					+ "          <label for=\"username\" class=\"sr-only\">Identity</label>\n"
					+ "          <input type=\"text\" id=\"username\" name=\"" + this.openIDusernameParameter + "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
					+ "        </p>\n"
					+ createRememberMe(this.openIDrememberMeParameter)
					+ renderHiddenInputs(request)
					+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
					+ "      </form>\n");
		}

		if (oauth2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with OAuth 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> clientAuthenticationUrlToClientName : oauth2AuthenticationUrlToClientName.entrySet()) {
				sb.append(" <tr><td>");
				String url = clientAuthenticationUrlToClientName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String clientName = HtmlUtils.htmlEscape(clientAuthenticationUrlToClientName.getValue());
				sb.append(clientName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table></div>\n");
		}

		sb.append("</body></html>");

		return sb.toString();
	}

	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			sb.append("<input name=\"").append(input.getKey()).append("\" type=\"hidden\" value=\"").append(input.getValue()).append("\" />\n");
		}
		return sb.toString();
	}

	private String createRememberMe(String paramName) {
		if (paramName == null) {
			return "";
		}
		return "<p><input type='checkbox' name='"
				+ paramName
				+ "'/> Remember me on this computer.</p>\n";
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

	private static String createError(boolean isError, String message) {
		return isError ? "<div class=\"alert alert-danger\" role=\"alert\">" + HtmlUtils.htmlEscape(message) + "</div>" : "";
	}

	private static String createLogoutSuccess(boolean isLogoutSuccess) {
		return isLogoutSuccess ? "<div class=\"alert alert-success\" role=\"alert\">You have been signed out</div>" : "";
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
