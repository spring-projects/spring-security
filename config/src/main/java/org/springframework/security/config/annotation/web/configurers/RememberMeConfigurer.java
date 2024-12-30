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

package org.springframework.security.config.annotation.web.configurers;

import java.util.UUID;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

/**
 * Configures Remember Me authentication. This typically involves the user checking a box
 * when they enter their username and password that states to "Remember Me".
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link RememberMeAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated
 *
 * <ul>
 * <li>
 * {@link HttpSecurity#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
 * is populated with a {@link RememberMeAuthenticationProvider}</li>
 * <li>{@link RememberMeServices} is populated as a shared object and available on
 * {@link HttpSecurity#getSharedObject(Class)}</li>
 * <li>{@link LogoutConfigurer#addLogoutHandler(LogoutHandler)} is used to add a logout
 * handler to clean up the remember me authentication.</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link AuthenticationManager}</li>
 * <li>{@link UserDetailsService} if no {@link #userDetailsService(UserDetailsService)}
 * was specified.</li>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if present will be populated with
 * information from the configuration</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Ngoc Nhan
 * @since 3.2
 */
public final class RememberMeConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<RememberMeConfigurer<H>, H> {

	/**
	 * The default name for remember me parameter name and remember me cookie name
	 */
	private static final String DEFAULT_REMEMBER_ME_NAME = "remember-me";

	private AuthenticationSuccessHandler authenticationSuccessHandler;

	private String key;

	private RememberMeServices rememberMeServices;

	private LogoutHandler logoutHandler;

	private String rememberMeParameter = DEFAULT_REMEMBER_ME_NAME;

	private String rememberMeCookieName = DEFAULT_REMEMBER_ME_NAME;

	private String rememberMeCookieDomain;

	private PersistentTokenRepository tokenRepository;

	private UserDetailsService userDetailsService;

	private Integer tokenValiditySeconds;

	private Boolean useSecureCookie;

	private Boolean alwaysRemember;

	/**
	 * Creates a new instance
	 */
	public RememberMeConfigurer() {
	}

	/**
	 * Allows specifying how long (in seconds) a token is valid for
	 * @param tokenValiditySeconds
	 * @return {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setTokenValiditySeconds(int)
	 */
	public RememberMeConfigurer<H> tokenValiditySeconds(int tokenValiditySeconds) {
		this.tokenValiditySeconds = tokenValiditySeconds;
		return this;
	}

	/**
	 * Whether the cookie should be flagged as secure or not. Secure cookies can only be
	 * sent over an HTTPS connection and thus cannot be accidentally submitted over HTTP
	 * where they could be intercepted.
	 * <p>
	 * By default the cookie will be secure if the request is secure. If you only want to
	 * use remember-me over HTTPS (recommended) you should set this property to
	 * {@code true}.
	 * @param useSecureCookie set to {@code true} to always user secure cookies,
	 * {@code false} to disable their use.
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setUseSecureCookie(boolean)
	 */
	public RememberMeConfigurer<H> useSecureCookie(boolean useSecureCookie) {
		this.useSecureCookie = useSecureCookie;
		return this;
	}

	/**
	 * Specifies the {@link UserDetailsService} used to look up the {@link UserDetails}
	 * when a remember me token is valid. When using a
	 * {@link org.springframework.security.web.SecurityFilterChain} bean, the default is
	 * to look for a {@link UserDetailsService} bean. Alternatively, one can populate
	 * {@link #rememberMeServices(RememberMeServices)}.
	 * @param userDetailsService the {@link UserDetailsService} to configure
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices
	 */
	public RememberMeConfigurer<H> userDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
		return this;
	}

	/**
	 * Specifies the {@link PersistentTokenRepository} to use. The default is to use
	 * {@link TokenBasedRememberMeServices} instead.
	 * @param tokenRepository the {@link PersistentTokenRepository} to use
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> tokenRepository(PersistentTokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
		return this;
	}

	/**
	 * Sets the key to identify tokens created for remember me authentication. Default is
	 * a secure randomly generated key. If {@link #rememberMeServices(RememberMeServices)}
	 * is specified and is of type {@link AbstractRememberMeServices}, then the default is
	 * the key set in {@link AbstractRememberMeServices}.
	 * @param key the key to identify tokens created for remember me authentication
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> key(String key) {
		this.key = key;
		return this;
	}

	/**
	 * The HTTP parameter used to indicate to remember the user at time of login.
	 * @param rememberMeParameter the HTTP parameter used to indicate to remember the user
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> rememberMeParameter(String rememberMeParameter) {
		this.rememberMeParameter = rememberMeParameter;
		return this;
	}

	/**
	 * The name of cookie which store the token for remember me authentication. Defaults
	 * to 'remember-me'.
	 * @param rememberMeCookieName the name of cookie which store the token for remember
	 * me authentication
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @since 4.0.1
	 */
	public RememberMeConfigurer<H> rememberMeCookieName(String rememberMeCookieName) {
		this.rememberMeCookieName = rememberMeCookieName;
		return this;
	}

	/**
	 * The domain name within which the remember me cookie is visible.
	 * @param rememberMeCookieDomain the domain name within which the remember me cookie
	 * is visible.
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @since 4.1.0
	 */
	public RememberMeConfigurer<H> rememberMeCookieDomain(String rememberMeCookieDomain) {
		this.rememberMeCookieDomain = rememberMeCookieDomain;
		return this;
	}

	/**
	 * Allows control over the destination a remembered user is sent to when they are
	 * successfully authenticated. By default, the filter will just allow the current
	 * request to proceed, but if an {@code AuthenticationSuccessHandler} is set, it will
	 * be invoked and the {@code doFilter()} method will return immediately, thus allowing
	 * the application to redirect the user to a specific URL, regardless of what the
	 * original request was for.
	 * @param authenticationSuccessHandler the strategy to invoke immediately before
	 * returning from {@code doFilter()}.
	 * @return {@link RememberMeConfigurer} for further customization
	 * @see RememberMeAuthenticationFilter#setAuthenticationSuccessHandler(AuthenticationSuccessHandler)
	 */
	public RememberMeConfigurer<H> authenticationSuccessHandler(
			AuthenticationSuccessHandler authenticationSuccessHandler) {
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		return this;
	}

	/**
	 * Specify the {@link RememberMeServices} to use.
	 * @param rememberMeServices the {@link RememberMeServices} to use
	 * @return the {@link RememberMeConfigurer} for further customizations
	 * @see RememberMeServices
	 */
	public RememberMeConfigurer<H> rememberMeServices(RememberMeServices rememberMeServices) {
		this.rememberMeServices = rememberMeServices;
		return this;
	}

	/**
	 * Whether the cookie should always be created even if the remember-me parameter is
	 * not set.
	 * <p>
	 * By default this will be set to {@code false}.
	 * @param alwaysRemember set to {@code true} to always trigger remember me,
	 * {@code false} to use the remember-me parameter.
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setAlwaysRemember(boolean)
	 */
	public RememberMeConfigurer<H> alwaysRemember(boolean alwaysRemember) {
		this.alwaysRemember = alwaysRemember;
		return this;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void init(H http) throws Exception {
		validateInput();
		String key = getKey();
		RememberMeServices rememberMeServices = getRememberMeServices(http, key);
		http.setSharedObject(RememberMeServices.class, rememberMeServices);
		LogoutConfigurer<H> logoutConfigurer = http.getConfigurer(LogoutConfigurer.class);
		if (logoutConfigurer != null && this.logoutHandler != null) {
			logoutConfigurer.addLogoutHandler(this.logoutHandler);
		}
		RememberMeAuthenticationProvider authenticationProvider = new RememberMeAuthenticationProvider(key);
		authenticationProvider = postProcess(authenticationProvider);
		http.authenticationProvider(authenticationProvider);
		initDefaultLoginFilter(http);
	}

	@Override
	public void configure(H http) {
		RememberMeAuthenticationFilter rememberMeFilter = new RememberMeAuthenticationFilter(
				http.getSharedObject(AuthenticationManager.class), this.rememberMeServices);
		if (this.authenticationSuccessHandler != null) {
			rememberMeFilter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
		}
		SecurityContextConfigurer<?> securityContextConfigurer = http.getConfigurer(SecurityContextConfigurer.class);
		if (securityContextConfigurer != null && securityContextConfigurer.isRequireExplicitSave()) {
			SecurityContextRepository securityContextRepository = securityContextConfigurer
				.getSecurityContextRepository();
			rememberMeFilter.setSecurityContextRepository(securityContextRepository);
		}
		rememberMeFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());

		SessionAuthenticationStrategy sessionAuthenticationStrategy = http
			.getSharedObject(SessionAuthenticationStrategy.class);
		if (sessionAuthenticationStrategy != null) {
			rememberMeFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
		}

		rememberMeFilter = postProcess(rememberMeFilter);
		http.addFilter(rememberMeFilter);
	}

	/**
	 * Validate rememberMeServices and rememberMeCookieName have not been set at the same
	 * time.
	 */
	private void validateInput() {
		if (this.rememberMeServices != null && !DEFAULT_REMEMBER_ME_NAME.equals(this.rememberMeCookieName)) {
			throw new IllegalArgumentException("Can not set rememberMeCookieName and custom rememberMeServices.");
		}
	}

	/**
	 * Returns the HTTP parameter used to indicate to remember the user at time of login.
	 * @return the HTTP parameter used to indicate to remember the user
	 */
	private String getRememberMeParameter() {
		return this.rememberMeParameter;
	}

	/**
	 * If available, initializes the {@link DefaultLoginPageGeneratingFilter} shared
	 * object.
	 * @param http the {@link HttpSecurityBuilder} to use
	 */
	private void initDefaultLoginFilter(H http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
			.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null) {
			loginPageGeneratingFilter.setRememberMeParameter(getRememberMeParameter());
		}
	}

	/**
	 * Gets the {@link RememberMeServices} or creates the {@link RememberMeServices}.
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key the {@link #key(String)}
	 * @return the {@link RememberMeServices} to use
	 * @throws Exception
	 */
	private RememberMeServices getRememberMeServices(H http, String key) throws Exception {
		if (this.rememberMeServices != null) {
			if (this.rememberMeServices instanceof LogoutHandler && this.logoutHandler == null) {
				this.logoutHandler = (LogoutHandler) this.rememberMeServices;
			}
			return this.rememberMeServices;
		}
		AbstractRememberMeServices tokenRememberMeServices = createRememberMeServices(http, key);
		tokenRememberMeServices.setParameter(this.rememberMeParameter);
		tokenRememberMeServices.setCookieName(this.rememberMeCookieName);
		if (this.rememberMeCookieDomain != null) {
			tokenRememberMeServices.setCookieDomain(this.rememberMeCookieDomain);
		}
		if (this.tokenValiditySeconds != null) {
			tokenRememberMeServices.setTokenValiditySeconds(this.tokenValiditySeconds);
		}
		if (this.useSecureCookie != null) {
			tokenRememberMeServices.setUseSecureCookie(this.useSecureCookie);
		}
		if (this.alwaysRemember != null) {
			tokenRememberMeServices.setAlwaysRemember(this.alwaysRemember);
		}
		tokenRememberMeServices.afterPropertiesSet();
		this.logoutHandler = tokenRememberMeServices;
		this.rememberMeServices = tokenRememberMeServices;
		return tokenRememberMeServices;
	}

	/**
	 * Creates the {@link RememberMeServices} to use when none is provided. The result is
	 * either {@link PersistentTokenRepository} (if a {@link PersistentTokenRepository} is
	 * specified, else {@link TokenBasedRememberMeServices}.
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key the {@link #key(String)}
	 * @return the {@link RememberMeServices} to use
	 */
	private AbstractRememberMeServices createRememberMeServices(H http, String key) {
		return (this.tokenRepository != null) ? createPersistentRememberMeServices(http, key)
				: createTokenBasedRememberMeServices(http, key);
	}

	/**
	 * Creates {@link TokenBasedRememberMeServices}
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key the {@link #key(String)}
	 * @return the {@link TokenBasedRememberMeServices}
	 */
	private AbstractRememberMeServices createTokenBasedRememberMeServices(H http, String key) {
		UserDetailsService userDetailsService = getUserDetailsService(http);
		return new TokenBasedRememberMeServices(key, userDetailsService);
	}

	/**
	 * Creates {@link PersistentTokenBasedRememberMeServices}
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key the {@link #key(String)}
	 * @return the {@link PersistentTokenBasedRememberMeServices}
	 */
	private AbstractRememberMeServices createPersistentRememberMeServices(H http, String key) {
		UserDetailsService userDetailsService = getUserDetailsService(http);
		return new PersistentTokenBasedRememberMeServices(key, userDetailsService, this.tokenRepository);
	}

	/**
	 * Gets the {@link UserDetailsService} to use. Either the explicitly configured
	 * {@link UserDetailsService} from {@link #userDetailsService(UserDetailsService)}, a
	 * shared object from {@link HttpSecurity#getSharedObject(Class)} or the
	 * {@link UserDetailsService} bean.
	 * @param http {@link HttpSecurity} to get the shared {@link UserDetailsService}
	 * @return the {@link UserDetailsService} to use
	 */
	private UserDetailsService getUserDetailsService(H http) {
		if (this.userDetailsService == null) {
			this.userDetailsService = getSharedOrBean(http, UserDetailsService.class);
		}
		Assert.state(this.userDetailsService != null,
				() -> "userDetailsService cannot be null. Invoke " + RememberMeConfigurer.class.getSimpleName()
						+ "#userDetailsService(UserDetailsService) or see its javadoc for alternative approaches.");
		return this.userDetailsService;
	}

	/**
	 * Gets the key to use for validating remember me tokens. If a value was passed into
	 * {@link #key(String)}, then that is returned. Alternatively, if a key was specified
	 * in the {@link #rememberMeServices(RememberMeServices)}}, then that is returned. If
	 * no key was specified in either of those cases, then a secure random string is
	 * generated.
	 * @return the remember me key to use
	 */
	private String getKey() {
		if (this.key == null) {
			if (this.rememberMeServices instanceof AbstractRememberMeServices) {
				this.key = ((AbstractRememberMeServices) this.rememberMeServices).getKey();
			}
			else {
				this.key = UUID.randomUUID().toString();
			}
		}
		return this.key;
	}

	private <C> C getSharedOrBean(H http, Class<C> type) {
		C shared = http.getSharedObject(type);
		if (shared != null) {
			return shared;
		}

		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		if (context == null) {
			return null;
		}
		return context.getBeanProvider(type).getIfUnique();
	}

}
