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
package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.DelegatingLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Adds logout support. Other {@link SecurityConfigurer} instances may invoke
 * {@link #addLogoutHandler(LogoutHandler)} in the {@link #init(HttpSecurityBuilder)} phase.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>
 * {@link LogoutFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared Objects are created
 *
 * <h2>Shared Objects Used</h2>
 *
 * No shared objects are used.
 *
 * @author Rob Winch
 * @since 3.2
 * @see RememberMeConfigurer
 */
public final class LogoutConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<LogoutConfigurer<H>, H> {
	private List<LogoutHandler> logoutHandlers = new ArrayList<>();
	private SecurityContextLogoutHandler contextLogoutHandler = new SecurityContextLogoutHandler();
	private String logoutSuccessUrl = "/login?logout";
	private LogoutSuccessHandler logoutSuccessHandler;
	private String logoutUrl = "/logout";
	private RequestMatcher logoutRequestMatcher;
	private boolean permitAll;
	private boolean customLogoutSuccess;

	private LinkedHashMap<RequestMatcher, LogoutSuccessHandler> defaultLogoutSuccessHandlerMappings =
			new LinkedHashMap<>();

	/**
	 * Creates a new instance
	 * @see HttpSecurity#logout()
	 */
	public LogoutConfigurer() {
	}

	/**
	 * Adds a {@link LogoutHandler}. The {@link SecurityContextLogoutHandler} is added as
	 * the last {@link LogoutHandler} by default.
	 *
	 * @param logoutHandler the {@link LogoutHandler} to add
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> addLogoutHandler(LogoutHandler logoutHandler) {
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.logoutHandlers.add(logoutHandler);
		return this;
	}

	/**
	 * Specifies if {@link SecurityContextLogoutHandler} should clear the {@link Authentication} at the time of logout.
	 * @param clearAuthentication true {@link SecurityContextLogoutHandler} should clear the {@link Authentication} (default), or false otherwise.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> clearAuthentication(boolean clearAuthentication) {
		contextLogoutHandler.setClearAuthentication(clearAuthentication);
		return this;
	}


	/**
	 * Configures {@link SecurityContextLogoutHandler} to invalidate the
	 * {@link HttpSession} at the time of logout.
	 * @param invalidateHttpSession true if the {@link HttpSession} should be invalidated
	 * (default), or false otherwise.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> invalidateHttpSession(boolean invalidateHttpSession) {
		contextLogoutHandler.setInvalidateHttpSession(invalidateHttpSession);
		return this;
	}

	/**
	 * The URL that triggers log out to occur (default is "/logout"). If CSRF protection
	 * is enabled (default), then the request must also be a POST. This means that by
	 * default POST "/logout" is required to trigger a log out. If CSRF protection is
	 * disabled, then any HTTP method is allowed.
	 *
	 * <p>
	 * It is considered best practice to use an HTTP POST on any action that changes state
	 * (i.e. log out) to protect against <a
	 * href="https://en.wikipedia.org/wiki/Cross-site_request_forgery">CSRF attacks</a>. If
	 * you really want to use an HTTP GET, you can use
	 * <code>logoutRequestMatcher(new AntPathRequestMatcher(logoutUrl, "GET"));</code>
	 * </p>
	 *
	 * @see #logoutRequestMatcher(RequestMatcher)
	 * @see HttpSecurity#csrf()
	 *
	 * @param logoutUrl the URL that will invoke logout.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> logoutUrl(String logoutUrl) {
		this.logoutRequestMatcher = null;
		this.logoutUrl = logoutUrl;
		return this;
	}

	/**
	 * The RequestMatcher that triggers log out to occur. In most circumstances users will
	 * use {@link #logoutUrl(String)} which helps enforce good practices.
	 *
	 * @see #logoutUrl(String)
	 *
	 * @param logoutRequestMatcher the RequestMatcher used to determine if logout should
	 * occur.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> logoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		this.logoutRequestMatcher = logoutRequestMatcher;
		return this;
	}

	/**
	 * The URL to redirect to after logout has occurred. The default is "/login?logout".
	 * This is a shortcut for invoking {@link #logoutSuccessHandler(LogoutSuccessHandler)}
	 * with a {@link SimpleUrlLogoutSuccessHandler}.
	 *
	 * @param logoutSuccessUrl the URL to redirect to after logout occurred
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> logoutSuccessUrl(String logoutSuccessUrl) {
		this.customLogoutSuccess = true;
		this.logoutSuccessUrl = logoutSuccessUrl;
		return this;
	}

	/**
	 * A shortcut for {@link #permitAll(boolean)} with <code>true</code> as an argument.
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> permitAll() {
		return permitAll(true);
	}

	/**
	 * Allows specifying the names of cookies to be removed on logout success. This is a
	 * shortcut to easily invoke {@link #addLogoutHandler(LogoutHandler)} with a
	 * {@link CookieClearingLogoutHandler}.
	 *
	 * @param cookieNamesToClear the names of cookies to be removed on logout success.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> deleteCookies(String... cookieNamesToClear) {
		return addLogoutHandler(new CookieClearingLogoutHandler(cookieNamesToClear));
	}

	/**
	 * Sets the {@link LogoutSuccessHandler} to use. If this is specified,
	 * {@link #logoutSuccessUrl(String)} is ignored.
	 *
	 * @param logoutSuccessHandler the {@link LogoutSuccessHandler} to use after a user
	 * has been logged out.
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> logoutSuccessHandler(
			LogoutSuccessHandler logoutSuccessHandler) {
		this.logoutSuccessUrl = null;
		this.customLogoutSuccess = true;
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	/**
	 * Sets a default {@link LogoutSuccessHandler} to be used which prefers being invoked
	 * for the provided {@link RequestMatcher}. If no {@link LogoutSuccessHandler} is
	 * specified a {@link SimpleUrlLogoutSuccessHandler} will be used.
	 * If any default {@link LogoutSuccessHandler} instances are configured, then a
	 * {@link DelegatingLogoutSuccessHandler} will be used that defaults to a
	 * {@link SimpleUrlLogoutSuccessHandler}.
	 *
	 * @param handler the {@link LogoutSuccessHandler} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 * {@link LogoutSuccessHandler}
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> defaultLogoutSuccessHandlerFor(
			LogoutSuccessHandler handler, RequestMatcher preferredMatcher) {
		Assert.notNull(handler, "handler cannot be null");
		Assert.notNull(preferredMatcher, "preferredMatcher cannot be null");
		this.defaultLogoutSuccessHandlerMappings.put(preferredMatcher, handler);
		return this;
	}

	/**
	 * Grants access to the {@link #logoutSuccessUrl(String)} and the
	 * {@link #logoutUrl(String)} for every user.
	 *
	 * @param permitAll if true grants access, else nothing is done
	 * @return the {@link LogoutConfigurer} for further customization.
	 */
	public LogoutConfigurer<H> permitAll(boolean permitAll) {
		this.permitAll = permitAll;
		return this;
	}

	/**
	 * Gets the {@link LogoutSuccessHandler} if not null, otherwise creates a new
	 * {@link SimpleUrlLogoutSuccessHandler} using the {@link #logoutSuccessUrl(String)}.
	 *
	 * @return the {@link LogoutSuccessHandler} to use
	 */
	private LogoutSuccessHandler getLogoutSuccessHandler() {
		LogoutSuccessHandler handler = this.logoutSuccessHandler;
		if (handler == null) {
			handler = createDefaultSuccessHandler();
		}
		return handler;
	}

	private LogoutSuccessHandler createDefaultSuccessHandler() {
		SimpleUrlLogoutSuccessHandler urlLogoutHandler = new SimpleUrlLogoutSuccessHandler();
		urlLogoutHandler.setDefaultTargetUrl(logoutSuccessUrl);
		if (defaultLogoutSuccessHandlerMappings.isEmpty()) {
			return urlLogoutHandler;
		}
		DelegatingLogoutSuccessHandler successHandler = new DelegatingLogoutSuccessHandler(defaultLogoutSuccessHandlerMappings);
		successHandler.setDefaultLogoutSuccessHandler(urlLogoutHandler);
		return successHandler;
	}

	@Override
	public void init(H http) throws Exception {
		if (permitAll) {
			PermitAllSupport.permitAll(http, this.logoutSuccessUrl);
			PermitAllSupport.permitAll(http, this.getLogoutRequestMatcher(http));
		}

		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null && !isCustomLogoutSuccess()) {
			loginPageGeneratingFilter.setLogoutSuccessUrl(getLogoutSuccessUrl());
		}
	}

	@Override
	public void configure(H http) throws Exception {
		LogoutFilter logoutFilter = createLogoutFilter(http);
		http.addFilter(logoutFilter);
	}

	/**
	 * Returns true if the logout success has been customized via
	 * {@link #logoutSuccessUrl(String)} or
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)}.
	 *
	 * @return true if logout success handling has been customized, else false
	 */
	boolean isCustomLogoutSuccess() {
		return customLogoutSuccess;
	}

	/**
	 * Gets the logoutSuccesUrl or null if a
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)} was configured.
	 *
	 * @return the logoutSuccessUrl
	 */
	private String getLogoutSuccessUrl() {
		return logoutSuccessUrl;
	}

	/**
	 * Gets the {@link LogoutHandler} instances that will be used.
	 * @return the {@link LogoutHandler} instances. Cannot be null.
	 */
	List<LogoutHandler> getLogoutHandlers() {
		return logoutHandlers;
	}

	/**
	 * Creates the {@link LogoutFilter} using the {@link LogoutHandler} instances, the
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)} and the
	 * {@link #logoutUrl(String)}.
	 *
	 * @param http the builder to use
	 * @return the {@link LogoutFilter} to use.
	 * @throws Exception
	 */
	private LogoutFilter createLogoutFilter(H http) throws Exception {
		logoutHandlers.add(contextLogoutHandler);
		LogoutHandler[] handlers = logoutHandlers
				.toArray(new LogoutHandler[logoutHandlers.size()]);
		LogoutFilter result = new LogoutFilter(getLogoutSuccessHandler(), handlers);
		result.setLogoutRequestMatcher(getLogoutRequestMatcher(http));
		result = postProcess(result);
		return result;
	}

	@SuppressWarnings("unchecked")
	private RequestMatcher getLogoutRequestMatcher(H http) {
		if (logoutRequestMatcher != null) {
			return logoutRequestMatcher;
		}
		if (http.getConfigurer(CsrfConfigurer.class) != null) {
			this.logoutRequestMatcher = new AntPathRequestMatcher(this.logoutUrl, "POST");
		}
		else {
			this.logoutRequestMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(this.logoutUrl, "GET"),
				new AntPathRequestMatcher(this.logoutUrl, "POST"),
				new AntPathRequestMatcher(this.logoutUrl, "PUT"),
				new AntPathRequestMatcher(this.logoutUrl, "DELETE")
			);
		}
		return this.logoutRequestMatcher;
	}
}
