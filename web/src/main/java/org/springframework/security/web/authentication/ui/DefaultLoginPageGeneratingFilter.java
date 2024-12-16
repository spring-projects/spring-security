/*
 * Copyright 2002-2024 the original author or authors.
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
import java.util.stream.Collectors;

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
import org.springframework.util.StringUtils;
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

	private boolean oauth2LoginEnabled;

	private boolean saml2LoginEnabled;

	private boolean passkeysEnabled;

	private boolean oneTimeTokenEnabled;

	private String authenticationUrl;

	private String generateOneTimeTokenUrl;

	private String usernameParameter;

	private String passwordParameter;

	private String rememberMeParameter;

	private Map<String, String> oauth2AuthenticationUrlToClientName;

	private Map<String, String> saml2AuthenticationUrlToProviderName;

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = (request) -> Collections.emptyMap();

	private Function<HttpServletRequest, Map<String, String>> resolveHeaders = (request) -> Collections.emptyMap();

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
		if (authFilter.getRememberMeServices() instanceof AbstractRememberMeServices rememberMeServices) {
			this.rememberMeParameter = rememberMeServices.getParameter();
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

	/**
	 * Sets a Function used to resolve a Map of the HTTP headers where the key is the name
	 * of the header and the value is the value of the header. Typically, this is used to
	 * resolve the CSRF token.
	 * @param resolveHeaders the function to resolve the headers
	 */
	public void setResolveHeaders(Function<HttpServletRequest, Map<String, String>> resolveHeaders) {
		Assert.notNull(resolveHeaders, "resolveHeaders cannot be null");
		this.resolveHeaders = resolveHeaders;
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

	public void setOneTimeTokenEnabled(boolean oneTimeTokenEnabled) {
		this.oneTimeTokenEnabled = oneTimeTokenEnabled;
	}

	public void setSaml2LoginEnabled(boolean saml2LoginEnabled) {
		this.saml2LoginEnabled = saml2LoginEnabled;
	}

	public void setPasskeysEnabled(boolean passkeysEnabled) {
		this.passkeysEnabled = passkeysEnabled;
	}

	public void setAuthenticationUrl(String authenticationUrl) {
		this.authenticationUrl = authenticationUrl;
	}

	public void setOneTimeTokenGenerationUrl(String generateOneTimeTokenUrl) {
		this.generateOneTimeTokenUrl = generateOneTimeTokenUrl;
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
		String errorMsg = loginError ? getLoginErrorMessage(request) : "Invalid credentials";
		String contextPath = request.getContextPath();

		return HtmlTemplates.fromTemplate(LOGIN_PAGE_TEMPLATE)
			.withRawHtml("contextPath", contextPath)
			.withRawHtml("javaScript", renderJavaScript(request, contextPath))
			.withRawHtml("formLogin", renderFormLogin(request, loginError, logoutSuccess, contextPath, errorMsg))
			.withRawHtml("oneTimeTokenLogin",
					renderOneTimeTokenLogin(request, loginError, logoutSuccess, contextPath, errorMsg))
			.withRawHtml("oauth2Login", renderOAuth2Login(loginError, logoutSuccess, errorMsg, contextPath))
			.withRawHtml("saml2Login", renderSaml2Login(loginError, logoutSuccess, errorMsg, contextPath))
			.withRawHtml("passkeyLogin", renderPasskeyLogin())
			.render();
	}

	private String renderJavaScript(HttpServletRequest request, String contextPath) {
		if (this.passkeysEnabled) {
			return HtmlTemplates.fromTemplate(PASSKEY_SCRIPT_TEMPLATE)
				.withValue("loginPageUrl", this.loginPageUrl)
				.withValue("contextPath", contextPath)
				.withRawHtml("csrfHeaders", renderHeaders(request))
				.render();
		}
		return "";
	}

	private String renderPasskeyLogin() {
		if (this.passkeysEnabled) {
			return PASSKEY_FORM_TEMPLATE;
		}
		return "";
	}

	private String renderHeaders(HttpServletRequest request) {
		StringBuffer javascriptHeadersEntries = new StringBuffer();
		Map<String, String> headers = this.resolveHeaders.apply(request);
		for (Map.Entry<String, String> header : headers.entrySet()) {
			javascriptHeadersEntries.append(HtmlTemplates.fromTemplate(CSRF_HEADERS)
				.withValue("headerName", header.getKey())
				.withValue("headerValue", header.getValue())
				.render());
		}
		return javascriptHeadersEntries.toString();
	}

	private String renderFormLogin(HttpServletRequest request, boolean loginError, boolean logoutSuccess,
			String contextPath, String errorMsg) {
		if (!this.formLoginEnabled) {
			return "";
		}

		String hiddenInputs = this.resolveHiddenInputs.apply(request)
			.entrySet()
			.stream()
			.map((inputKeyValue) -> renderHiddenInput(inputKeyValue.getKey(), inputKeyValue.getValue()))
			.collect(Collectors.joining("\n"));

		return HtmlTemplates.fromTemplate(LOGIN_FORM_TEMPLATE)
			.withValue("loginUrl", contextPath + this.authenticationUrl)
			.withRawHtml("errorMessage", renderError(loginError, errorMsg))
			.withRawHtml("logoutMessage", renderSuccess(logoutSuccess))
			.withValue("usernameParameter", this.usernameParameter)
			.withValue("passwordParameter", this.passwordParameter)
			.withRawHtml("rememberMeInput", renderRememberMe(this.rememberMeParameter))
			.withRawHtml("hiddenInputs", hiddenInputs)
			.withValue("autocomplete", this.passkeysEnabled ? "autocomplete=\"password webauthn\"" : "")
			.render();
	}

	private String renderOneTimeTokenLogin(HttpServletRequest request, boolean loginError, boolean logoutSuccess,
			String contextPath, String errorMsg) {
		if (!this.oneTimeTokenEnabled) {
			return "";
		}

		String hiddenInputs = this.resolveHiddenInputs.apply(request)
			.entrySet()
			.stream()
			.map((inputKeyValue) -> renderHiddenInput(inputKeyValue.getKey(), inputKeyValue.getValue()))
			.collect(Collectors.joining("\n"));

		return HtmlTemplates.fromTemplate(ONE_TIME_TEMPLATE)
			.withValue("generateOneTimeTokenUrl", contextPath + this.generateOneTimeTokenUrl)
			.withRawHtml("errorMessage", renderError(loginError, errorMsg))
			.withRawHtml("logoutMessage", renderSuccess(logoutSuccess))
			.withRawHtml("hiddenInputs", hiddenInputs)
			.render();
	}

	private String renderOAuth2Login(boolean loginError, boolean logoutSuccess, String errorMsg, String contextPath) {
		if (!this.oauth2LoginEnabled) {
			return "";
		}

		String oauth2Rows = this.oauth2AuthenticationUrlToClientName.entrySet()
			.stream()
			.map((urlToName) -> renderOAuth2Row(contextPath, urlToName.getKey(), urlToName.getValue()))
			.collect(Collectors.joining("\n"));

		return HtmlTemplates.fromTemplate(OAUTH2_LOGIN_TEMPLATE)
			.withRawHtml("errorMessage", renderError(loginError, errorMsg))
			.withRawHtml("logoutMessage", renderSuccess(logoutSuccess))
			.withRawHtml("oauth2Rows", oauth2Rows)
			.render();
	}

	private static String renderOAuth2Row(String contextPath, String url, String clientName) {
		return HtmlTemplates.fromTemplate(OAUTH2_ROW_TEMPLATE)
			.withValue("url", contextPath + url)
			.withValue("clientName", clientName)
			.render();
	}

	private String renderSaml2Login(boolean loginError, boolean logoutSuccess, String errorMsg, String contextPath) {
		if (!this.saml2LoginEnabled) {
			return "";
		}

		String samlRows = this.saml2AuthenticationUrlToProviderName.entrySet()
			.stream()
			.map((urlToName) -> renderSaml2Row(contextPath, urlToName.getKey(), urlToName.getValue()))
			.collect(Collectors.joining("\n"));

		return HtmlTemplates.fromTemplate(SAML_LOGIN_TEMPLATE)
			.withRawHtml("errorMessage", renderError(loginError, errorMsg))
			.withRawHtml("logoutMessage", renderSuccess(logoutSuccess))
			.withRawHtml("samlRows", samlRows)
			.render();
	}

	private static String renderSaml2Row(String contextPath, String url, String clientName) {
		return HtmlTemplates.fromTemplate(SAML_ROW_TEMPLATE)
			.withValue("url", contextPath + url)
			.withValue("clientName", clientName)
			.render();
	}

	private String getLoginErrorMessage(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return "Invalid credentials";
		}
		if (!(session
			.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) instanceof AuthenticationException exception)) {
			return "Invalid credentials";
		}
		if (!StringUtils.hasText(exception.getMessage())) {
			return "Invalid credentials";
		}
		return exception.getMessage();
	}

	private String renderHiddenInput(String name, String value) {
		return HtmlTemplates.fromTemplate(HIDDEN_HTML_INPUT_TEMPLATE)
			.withValue("name", name)
			.withValue("value", value)
			.render();
	}

	private String renderRememberMe(String paramName) {
		if (paramName == null) {
			return "";
		}
		return HtmlTemplates
			.fromTemplate("<p><input type='checkbox' name='{{paramName}}'/> Remember me on this computer.</p>")
			.withValue("paramName", paramName)
			.render();
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

	private String renderError(boolean isError, String message) {
		if (!isError) {
			return "";
		}
		return HtmlTemplates.fromTemplate(ALERT_TEMPLATE).withValue("message", message).render();
	}

	private String renderSuccess(boolean isLogoutSuccess) {
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

	private static final String CSRF_HEADERS = """
			{"{{headerName}}" : "{{headerValue}}"}""";

	private static final String PASSKEY_SCRIPT_TEMPLATE = """
				<script type="text/javascript" src="{{contextPath}}/login/webauthn.js"></script>
				<script type="text/javascript">
				<!--
					document.addEventListener("DOMContentLoaded",() => setupLogin({{csrfHeaders}}, "{{contextPath}}", document.getElementById('passkey-signin')));

				//-->
				</script>
			""";

	private static final String PASSKEY_FORM_TEMPLATE = """
			<div class="login-form">
			<h2>Login with Passkeys</h2>
			<button id="passkey-signin" type="submit" class="primary">Sign in with a passkey</button>
			</form>
			""";

	private static final String LOGIN_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <meta charset="utf-8">
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			    <meta name="description" content="">
			    <meta name="author" content="">
			    <title>Please sign in</title>
			    <link href="{{contextPath}}/default-ui.css" rel="stylesheet" />{{javaScript}}
			  </head>
			  <body>
			    <div class="content">
			{{formLogin}}
			{{oneTimeTokenLogin}}{{passkeyLogin}}
			{{oauth2Login}}
			{{saml2Login}}
			    </div>
			  </body>
			</html>""";

	private static final String LOGIN_FORM_TEMPLATE = """
			      <form class="login-form" method="post" action="{{loginUrl}}">
			        <h2>Please sign in</h2>
			{{errorMessage}}{{logoutMessage}}
			        <p>
			          <label for="username" class="screenreader">Username</label>
			          <input type="text" id="username" name="{{usernameParameter}}" placeholder="Username" required autofocus>
			        </p>
			        <p>
			          <label for="password" class="screenreader">Password</label>
			          <input type="password" id="password" name="{{passwordParameter}}" placeholder="Password" {{autocomplete}}required>
			        </p>
			{{rememberMeInput}}
			{{hiddenInputs}}
			        <button type="submit" class="primary">Sign in</button>
			      </form>""";

	private static final String HIDDEN_HTML_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

	private static final String ALERT_TEMPLATE = """
			<div class="alert alert-danger" role="alert">{{message}}</div>""";

	private static final String OAUTH2_LOGIN_TEMPLATE = """
			<h2>Login with OAuth 2.0</h2>
			{{errorMessage}}{{logoutMessage}}
			<table class="table table-striped">
			  {{oauth2Rows}}
			</table>""";

	private static final String OAUTH2_ROW_TEMPLATE = """
			<tr><td><a href="{{url}}">{{clientName}}</a></td></tr>""";

	private static final String SAML_LOGIN_TEMPLATE = """
			<h2>Login with SAML 2.0</h2>
			{{errorMessage}}{{logoutMessage}}
			<table class="table table-striped">
			  {{samlRows}}
			</table>""";

	private static final String SAML_ROW_TEMPLATE = OAUTH2_ROW_TEMPLATE;

	private static final String ONE_TIME_TEMPLATE = """
			      <form id="ott-form" class="login-form" method="post" action="{{generateOneTimeTokenUrl}}">
			        <h2>Request a One-Time Token</h2>
			{{errorMessage}}{{logoutMessage}}
			        <p>
			          <label for="ott-username" class="screenreader">Username</label>
			          <input type="text" id="ott-username" name="username" placeholder="Username" required>
			        </p>
			{{hiddenInputs}}
			        <button class="primary" type="submit" form="ott-form">Send Token</button>
			      </form>
			""";

}
