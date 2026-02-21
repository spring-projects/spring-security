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
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.core.log.LogMessage;
import org.springframework.lang.Contract;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Processes a HTTP request's BASIC authorization headers, putting the result into the
 * <code>SecurityContextHolder</code>.
 *
 * <p>
 * For a detailed background on what this filter is designed to process, refer to
 * <a href="https://tools.ietf.org/html/rfc1945">RFC 1945, Section 11.1</a>. Any realm
 * name presented in the HTTP request is ignored.
 *
 * <p>
 * In summary, this filter is responsible for processing any request that has a HTTP
 * request header of <code>Authorization</code> with an authentication scheme of
 * <code>Basic</code> and a Base64-encoded <code>username:password</code> token. For
 * example, to authenticate user "Aladdin" with password "open sesame" the following
 * header would be presented:
 *
 * <pre>
 *
 * Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
 * </pre>
 *
 * <p>
 * This filter can be used to provide BASIC authentication services to both remoting
 * protocol clients (such as Hessian and SOAP) as well as standard user agents (such as
 * Internet Explorer and Netscape).
 * <p>
 * If authentication is successful, the resulting {@link Authentication} object will be
 * placed into the <code>SecurityContextHolder</code>.
 *
 * <p>
 * If authentication fails and <code>ignoreFailure</code> is <code>false</code> (the
 * default), an {@link AuthenticationEntryPoint} implementation is called (unless the
 * <tt>ignoreFailure</tt> property is set to <tt>true</tt>). Usually this should be
 * {@link BasicAuthenticationEntryPoint}, which will prompt the user to authenticate again
 * via BASIC authentication.
 *
 * <p>
 * Basic authentication is an attractive protocol because it is simple and widely
 * deployed. However, it still transmits a password in clear text and as such is
 * undesirable in many situations.
 * <p>
 * Note that if a {@link RememberMeServices} is set, this filter will automatically send
 * back remember-me details to the client. Therefore, subsequent requests will not need to
 * present a BASIC authentication header as they will be authenticated using the
 * remember-me mechanism.
 *
 * @author Ben Alex
 * @author Andrey Litvitski
 */
public class BasicAuthenticationFilter extends OncePerRequestFilter {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private @Nullable AuthenticationEntryPoint authenticationEntryPoint;

	private AuthenticationManager authenticationManager;

	private RememberMeServices rememberMeServices = new NullRememberMeServices();

	private boolean ignoreFailure = false;

	private String credentialsCharset = "UTF-8";

	private AuthenticationConverter authenticationConverter = new BasicAuthenticationConverter();

	private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

	private boolean mfaEnabled;

	/**
	 * Creates an instance which will authenticate against the supplied
	 * {@code AuthenticationManager} and which will ignore failed authentication attempts,
	 * allowing the request to proceed down the filter chain.
	 * @param authenticationManager the bean to submit authentication requests to
	 */
	public BasicAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		this.ignoreFailure = true;
	}

	/**
	 * Creates an instance which will authenticate against the supplied
	 * {@code AuthenticationManager} and use the supplied {@code AuthenticationEntryPoint}
	 * to handle authentication failures.
	 * @param authenticationManager the bean to submit authentication requests to
	 * @param authenticationEntryPoint will be invoked when authentication fails.
	 * Typically an instance of {@link BasicAuthenticationEntryPoint}.
	 */
	public BasicAuthenticationFilter(AuthenticationManager authenticationManager,
			AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationManager = authenticationManager;
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * Sets the {@link SecurityContextRepository} to save the {@link SecurityContext} on
	 * authentication success. The default action is not to save the
	 * {@link SecurityContext}.
	 * @param securityContextRepository the {@link SecurityContextRepository} to use.
	 * Cannot be null.
	 */
	public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	/**
	 * Enables Multi-Factor Authentication (MFA) support.
	 * @param mfaEnabled true to enable MFA support, false to disable it. Default is
	 * false.
	 */
	public void setMfaEnabled(boolean mfaEnabled) {
		this.mfaEnabled = mfaEnabled;
	}

	/**
	 * Sets the
	 * {@link org.springframework.security.web.authentication.AuthenticationConverter} to
	 * use. Defaults to {@link BasicAuthenticationConverter}
	 * @param authenticationConverter the converter to use
	 * @since 6.2
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
		if (!isIgnoreFailure()) {
			Assert.notNull(this.authenticationEntryPoint, "An AuthenticationEntryPoint is required");
		}
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		try {
			Authentication authRequest = this.authenticationConverter.convert(request);
			if (authRequest == null) {
				this.logger.trace("Did not process authentication request since failed to find "
						+ "username and password in Basic Authorization header");
				chain.doFilter(request, response);
				return;
			}
			String username = authRequest.getName();
			this.logger.trace(LogMessage.format("Found username '%s' in Basic Authorization header", username));
			if (authenticationIsRequired(username)) {
				Authentication authResult = this.authenticationManager.authenticate(authRequest);
				Authentication current = this.securityContextHolderStrategy.getContext().getAuthentication();
				if (shouldPerformMfa(current, authResult)) {
					authResult = authResult.toBuilder()
					// @formatter:off
						.authorities((a) -> {
							Set<String> newAuthorities = a.stream()
								.map(GrantedAuthority::getAuthority)
								.collect(Collectors.toUnmodifiableSet());
							for (GrantedAuthority currentAuthority : current.getAuthorities()) {
								if (!newAuthorities.contains(currentAuthority.getAuthority())) {
									a.add(currentAuthority);
								}
							}
						})
						.build();
						// @formatter:on
				}
				SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
				context.setAuthentication(authResult);
				this.securityContextHolderStrategy.setContext(context);
				if (this.logger.isDebugEnabled()) {
					this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
				}
				this.rememberMeServices.loginSuccess(request, response, authResult);
				this.securityContextRepository.saveContext(context, request, response);
				onSuccessfulAuthentication(request, response, authResult);
			}
		}
		catch (AuthenticationException ex) {
			this.securityContextHolderStrategy.clearContext();
			this.logger.debug("Failed to process authentication request", ex);
			this.rememberMeServices.loginFail(request, response);
			onUnsuccessfulAuthentication(request, response, ex);
			if (this.ignoreFailure || this.authenticationEntryPoint == null) {
				chain.doFilter(request, response);
			}
			else {
				this.authenticationEntryPoint.commence(request, response, ex);
			}
			return;
		}

		chain.doFilter(request, response);
	}

	@Contract("null, _ -> false")
	private boolean shouldPerformMfa(@Nullable Authentication current, Authentication authenticationResult) {
		if (!this.mfaEnabled) {
			return false;
		}
		if (current == null || !current.isAuthenticated()) {
			return false;
		}
		if (!declaresToBuilder(authenticationResult)) {
			return false;
		}
		return current.getName().equals(authenticationResult.getName());
	}

	private static boolean declaresToBuilder(Authentication authentication) {
		for (Method method : authentication.getClass().getDeclaredMethods()) {
			if (method.getName().equals("toBuilder") && method.getParameterTypes().length == 0) {
				return true;
			}
		}
		return false;
	}

	protected boolean authenticationIsRequired(String username) {
		// Only reauthenticate if username doesn't match SecurityContextHolder and user
		// isn't authenticated (see SEC-53)
		Authentication existingAuth = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (existingAuth == null || !existingAuth.getName().equals(username) || !existingAuth.isAuthenticated()) {
			return true;
		}
		// Handle unusual condition where an AnonymousAuthenticationToken is already
		// present. This shouldn't happen very often, as BasicAuthenticationFilter is
		// meant to
		// be earlier in the filter chain than AnonymousAuthenticationFilter.
		// Nevertheless, presence of both an AnonymousAuthenticationToken together with a
		// BASIC authentication request header should indicate reauthentication using the
		// BASIC protocol is desirable. This behaviour is also consistent with that
		// provided by form and digest, both of which force re-authentication if the
		// respective header is detected (and in doing so replace/ any existing
		// AnonymousAuthenticationToken). See SEC-610.
		return (existingAuth instanceof AnonymousAuthenticationToken);
	}

	protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			Authentication authResult) throws IOException {
	}

	protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException {
	}

	protected @Nullable AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	protected AuthenticationManager getAuthenticationManager() {
		return this.authenticationManager;
	}

	protected boolean isIgnoreFailure() {
		return this.ignoreFailure;
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

	/**
	 * Sets the {@link AuthenticationDetailsSource} to use. By default, it is set to use
	 * the {@link WebAuthenticationDetailsSource}. Note that this configuration applies
	 * exclusively when the {@link #authenticationConverter} is set to
	 * {@link BasicAuthenticationConverter}. If you are utilizing a different
	 * implementation, you will need to manually specify the authentication details on it.
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} to use.
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		if (this.authenticationConverter instanceof BasicAuthenticationConverter basicAuthenticationConverter) {
			basicAuthenticationConverter.setAuthenticationDetailsSource(authenticationDetailsSource);
		}
	}

	public void setRememberMeServices(RememberMeServices rememberMeServices) {
		Assert.notNull(rememberMeServices, "rememberMeServices cannot be null");
		this.rememberMeServices = rememberMeServices;
	}

	/**
	 * Sets the charset to use when decoding credentials to {@link String}s. By default,
	 * it is set to {@code UTF-8}. Note that this configuration applies exclusively when
	 * the {@link #authenticationConverter} is set to
	 * {@link BasicAuthenticationConverter}. If you are utilizing a different
	 * implementation, you will need to manually specify the charset on it.
	 * @param credentialsCharset the charset to use.
	 */
	public void setCredentialsCharset(String credentialsCharset) {
		Assert.hasText(credentialsCharset, "credentialsCharset cannot be null or empty");
		this.credentialsCharset = credentialsCharset;
		if (this.authenticationConverter instanceof BasicAuthenticationConverter basicAuthenticationConverter) {
			Charset charset = Charset.forName(credentialsCharset);
			basicAuthenticationConverter.setCredentialsCharset(charset);
			if (this.authenticationEntryPoint instanceof BasicAuthenticationEntryPoint basicAuthenticationEntryPoint) {
				basicAuthenticationEntryPoint.setCharset(charset);
			}
		}
	}

	protected String getCredentialsCharset(HttpServletRequest httpRequest) {
		return this.credentialsCharset;
	}

}
