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

package org.springframework.security.web.servletapi;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * A <code>Filter</code> which populates the <code>ServletRequest</code> with a request
 * wrapper which implements the servlet API security methods.
 * <p>
 * {@link SecurityContextHolderAwareRequestWrapper} is extended to provide the following
 * additional methods:
 * </p>
 * <ul>
 * <li>{@link HttpServletRequest#authenticate(HttpServletResponse)} - Allows the user to
 * determine if they are authenticated and if not send the user to the login page. See
 * {@link #setAuthenticationEntryPoint(AuthenticationEntryPoint)}.</li>
 * <li>{@link HttpServletRequest#login(String, String)} - Allows the user to authenticate
 * using the {@link AuthenticationManager}. See
 * {@link #setAuthenticationManager(AuthenticationManager)}.</li>
 * <li>{@link HttpServletRequest#logout()} - Allows the user to logout using the
 * {@link LogoutHandler}s configured in Spring Security. See
 * {@link #setLogoutHandlers(List)}.</li>
 * <li>{@link AsyncContext#start(Runnable)} - Automatically copy the
 * {@link SecurityContext} from the {@link SecurityContextHolder} found on the Thread that
 * invoked {@link AsyncContext#start(Runnable)} to the Thread that processes the
 * {@link Runnable}.</li>
 * </ul>
 *
 * @author Orlando Garcia Carmona
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 * @author Eddú Meléndez
 */
public class SecurityContextHolderAwareRequestFilter extends GenericFilterBean {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private String rolePrefix = "ROLE_";

	@SuppressWarnings("NullAway.Init")
	private HttpServletRequestFactory requestFactory;

	private @Nullable AuthenticationEntryPoint authenticationEntryPoint;

	private @Nullable AuthenticationManager authenticationManager;

	private @Nullable List<LogoutHandler> logoutHandlers;

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

	/**
	 * Sets the {@link SecurityContextRepository} to use. The default is to use
	 * {@link HttpSessionSecurityContextRepository}.
	 * @param securityContextRepository the {@link SecurityContextRepository} to use.
	 * @since 6.0
	 */
	public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "Role prefix must not be null");
		this.rolePrefix = rolePrefix;
		updateFactory();
	}

	/**
	 * <p>
	 * Sets the {@link AuthenticationEntryPoint} used when integrating
	 * {@link HttpServletRequest} with Servlet 3 APIs. Specifically, it will be used when
	 * {@link HttpServletRequest#authenticate(HttpServletResponse)} is called and the user
	 * is not authenticated.
	 * </p>
	 * <p>
	 * If the value is null (default), then the default container behavior will be be
	 * retained when invoking {@link HttpServletRequest#authenticate(HttpServletResponse)}
	 * .
	 * </p>
	 * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use when
	 * invoking {@link HttpServletRequest#authenticate(HttpServletResponse)} if the user
	 * is not authenticated.
	 */
	public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * <p>
	 * Sets the {@link AuthenticationManager} used when integrating
	 * {@link HttpServletRequest} with Servlet 3 APIs. Specifically, it will be used when
	 * {@link HttpServletRequest#login(String, String)} is invoked to determine if the
	 * user is authenticated.
	 * </p>
	 * <p>
	 * If the value is null (default), then the default container behavior will be
	 * retained when invoking {@link HttpServletRequest#login(String, String)}.
	 * </p>
	 * @param authenticationManager the {@link AuthenticationManager} to use when invoking
	 * {@link HttpServletRequest#login(String, String)}
	 */
	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	/**
	 * <p>
	 * Sets the {@link LogoutHandler}s used when integrating with
	 * {@link HttpServletRequest} with Servlet 3 APIs. Specifically it will be used when
	 * {@link HttpServletRequest#logout()} is invoked in order to log the user out. So
	 * long as the {@link LogoutHandler}s do not commit the {@link HttpServletResponse}
	 * (expected), then the user is in charge of handling the response.
	 * </p>
	 * <p>
	 * If the value is null (default), the default container behavior will be retained
	 * when invoking {@link HttpServletRequest#logout()}.
	 * </p>
	 * @param logoutHandlers the {@code List&lt;LogoutHandler&gt;}s when invoking
	 * {@link HttpServletRequest#logout()}.
	 */
	public void setLogoutHandlers(List<LogoutHandler> logoutHandlers) {
		this.logoutHandlers = logoutHandlers;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		chain.doFilter(this.requestFactory.create((HttpServletRequest) req, (HttpServletResponse) res), res);
	}

	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();
		updateFactory();
	}

	private void updateFactory() {
		String rolePrefix = this.rolePrefix;
		this.requestFactory = createServlet3Factory(rolePrefix);
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
		updateFactory();
	}

	private HttpServletRequestFactory createServlet3Factory(String rolePrefix) {
		HttpServlet3RequestFactory factory = new HttpServlet3RequestFactory(rolePrefix, this.securityContextRepository);
		factory.setTrustResolver(this.trustResolver);
		factory.setAuthenticationEntryPoint(this.authenticationEntryPoint);
		factory.setAuthenticationManager(this.authenticationManager);
		factory.setLogoutHandlers(this.logoutHandlers);
		factory.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		return factory;
	}

}
