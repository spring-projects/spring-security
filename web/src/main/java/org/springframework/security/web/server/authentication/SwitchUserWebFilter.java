/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.server.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * Switch User processing filter responsible for user context switching. A common use-case
 * for this feature is the ability to allow higher-authority users (e.g. ROLE_ADMIN) to
 * switch to a regular user (e.g. ROLE_USER).
 * <p>
 * This filter assumes that the user performing the switch will be required to be logged
 * in as normal user (i.e. with a ROLE_ADMIN role). The user will then access a
 * page/controller that enables the administrator to specify who they wish to become (see
 * <code>switchUserUrl</code>).
 * <p>
 * <b>Note: This URL will be required to have appropriate security constraints configured
 * so that only users of that role can access it (e.g. ROLE_ADMIN).</b>
 * <p>
 * On a successful switch, the user's <code>SecurityContext</code> will be updated to
 * reflect the specified user and will also contain an additional
 * {@link org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority}
 * which contains the original user. Before switching, a check will be made on whether the
 * user is already currently switched, and any current switch will be exited to prevent
 * "nested" switches.
 * <p>
 * To 'exit' from a user context, the user needs to access a URL (see
 * <code>exitUserUrl</code>) that will switch back to the original user as identified by
 * the <code>ROLE_PREVIOUS_ADMINISTRATOR</code>.
 * <p>
 * To configure the Switch User Processing Filter, create a bean definition for the Switch
 * User processing filter and add to the filterChainProxy. Note that the filter must come
 * <b>after</b> the
 * {@link org.springframework.security.config.web.server.SecurityWebFiltersOrder#AUTHORIZATION}
 * in the chain, in order to apply the correct constraints to the <tt>switchUserUrl</tt>.
 * Example: <pre>
 * SwitchUserWebFilter filter = new SwitchUserWebFilter(userDetailsService, loginSuccessHandler, failureHandler);
 * http.addFilterAfter(filter, SecurityWebFiltersOrder.AUTHORIZATION);
 * </pre>
 *
 * @author Artur Otrzonsek
 * @since 5.4
 * @see SwitchUserGrantedAuthority
 */
public class SwitchUserWebFilter implements WebFilter {

	private final Log logger = LogFactory.getLog(getClass());

	public static final String SPRING_SECURITY_SWITCH_USERNAME_KEY = "username";

	public static final String ROLE_PREVIOUS_ADMINISTRATOR = "ROLE_PREVIOUS_ADMINISTRATOR";

	private final ServerAuthenticationSuccessHandler successHandler;

	private final ServerAuthenticationFailureHandler failureHandler;

	private final ReactiveUserDetailsService userDetailsService;

	private final UserDetailsChecker userDetailsChecker;

	private ServerSecurityContextRepository securityContextRepository;

	private ServerWebExchangeMatcher switchUserMatcher = createMatcher("/login/impersonate");

	private ServerWebExchangeMatcher exitUserMatcher = createMatcher("/logout/impersonate");

	/**
	 * Creates a filter for the user context switching
	 * @param userDetailsService The <tt>UserDetailService</tt> which will be used to load
	 * information for the user that is being switched to.
	 * @param successHandler Used to define custom behaviour on a successful switch or
	 * exit user.
	 * @param failureHandler Used to define custom behaviour when a switch fails.
	 */
	public SwitchUserWebFilter(ReactiveUserDetailsService userDetailsService,
			ServerAuthenticationSuccessHandler successHandler,
			@Nullable ServerAuthenticationFailureHandler failureHandler) {
		Assert.notNull(userDetailsService, "userDetailsService must be specified");
		Assert.notNull(successHandler, "successHandler must be specified");

		this.userDetailsService = userDetailsService;
		this.successHandler = successHandler;
		this.failureHandler = failureHandler;

		this.securityContextRepository = new WebSessionServerSecurityContextRepository();
		this.userDetailsChecker = new AccountStatusUserDetailsChecker();
	}

	/**
	 * Creates a filter for the user context switching
	 * @param userDetailsService The <tt>UserDetailService</tt> which will be used to load
	 * information for the user that is being switched to.
	 * @param successTargetUrl Sets the URL to go to after a successful switch / exit user
	 * request
	 * @param failureTargetUrl The URL to which a user should be redirected if the switch
	 * fails
	 */
	public SwitchUserWebFilter(ReactiveUserDetailsService userDetailsService, String successTargetUrl,
			@Nullable String failureTargetUrl) {
		Assert.notNull(userDetailsService, "userDetailsService must be specified");
		Assert.notNull(successTargetUrl, "successTargetUrl must be specified");

		this.userDetailsService = userDetailsService;
		this.successHandler = new RedirectServerAuthenticationSuccessHandler(successTargetUrl);

		if (failureTargetUrl != null) {
			this.failureHandler = new RedirectServerAuthenticationFailureHandler(failureTargetUrl);
		}
		else {
			this.failureHandler = null;
		}

		this.securityContextRepository = new WebSessionServerSecurityContextRepository();
		this.userDetailsChecker = new AccountStatusUserDetailsChecker();
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		final WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, chain);

		return switchUser(webFilterExchange).switchIfEmpty(Mono.defer(() -> exitSwitchUser(webFilterExchange)))
				.switchIfEmpty(Mono.defer(() -> chain.filter(exchange).then(Mono.empty())))
				.flatMap((authentication) -> onAuthenticationSuccess(authentication, webFilterExchange))
				.onErrorResume(SwitchUserAuthenticationException.class, (exception) -> Mono.empty());
	}

	/**
	 * Attempt to switch to another user.
	 * @param webFilterExchange The web filter exchange
	 * @return The new <code>Authentication</code> object if successfully switched to
	 * another user, <code>Mono.empty()</code> otherwise.
	 * @throws AuthenticationCredentialsNotFoundException If the target user can not be
	 * found by username
	 */
	protected Mono<Authentication> switchUser(WebFilterExchange webFilterExchange) {
		return this.switchUserMatcher.matches(webFilterExchange.getExchange())
				.filter(ServerWebExchangeMatcher.MatchResult::isMatch)
				.flatMap((matchResult) -> ReactiveSecurityContextHolder.getContext())
				.map(SecurityContext::getAuthentication).flatMap((currentAuthentication) -> {
					final String username = getUsername(webFilterExchange.getExchange());
					return attemptSwitchUser(currentAuthentication, username);
				}).onErrorResume(AuthenticationException.class, (e) -> onAuthenticationFailure(e, webFilterExchange)
						.then(Mono.error(new SwitchUserAuthenticationException(e))));
	}

	/**
	 * Attempt to exit from an already switched user.
	 * @param webFilterExchange The web filter exchange
	 * @return The original <code>Authentication</code> object.
	 * @throws AuthenticationCredentialsNotFoundException If there is no
	 * <code>Authentication</code> associated with this request or the user is not
	 * switched.
	 */
	protected Mono<Authentication> exitSwitchUser(WebFilterExchange webFilterExchange) {
		return this.exitUserMatcher.matches(webFilterExchange.getExchange())
				.filter(ServerWebExchangeMatcher.MatchResult::isMatch)
				.flatMap((matchResult) -> ReactiveSecurityContextHolder.getContext()
						.map(SecurityContext::getAuthentication)
						.switchIfEmpty(Mono.error(this::noCurrentUserException)))
				.map(this::attemptExitUser);
	}

	/**
	 * Returns the name of the target user.
	 * @param exchange The server web exchange
	 * @return the name of the target user.
	 */
	protected String getUsername(ServerWebExchange exchange) {
		return exchange.getRequest().getQueryParams().getFirst(SPRING_SECURITY_SWITCH_USERNAME_KEY);
	}

	@NonNull
	private Mono<Authentication> attemptSwitchUser(Authentication currentAuthentication, String userName) {
		Assert.notNull(userName, "The userName can not be null.");

		if (this.logger.isDebugEnabled()) {
			this.logger.debug("Attempt to switch to user [" + userName + "]");
		}

		return this.userDetailsService.findByUsername(userName)
				.switchIfEmpty(Mono.error(this::noTargetAuthenticationException))
				.doOnNext(this.userDetailsChecker::check)
				.map((userDetails) -> createSwitchUserToken(userDetails, currentAuthentication));
	}

	@NonNull
	private Authentication attemptExitUser(Authentication currentAuthentication) {
		final Optional<Authentication> sourceAuthentication = extractSourceAuthentication(currentAuthentication);

		if (!sourceAuthentication.isPresent()) {
			this.logger.debug("Could not find original user Authentication object!");
			throw noOriginalAuthenticationException();
		}

		return sourceAuthentication.get();
	}

	private Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
		final ServerWebExchange exchange = webFilterExchange.getExchange();
		final SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		return this.securityContextRepository.save(exchange, securityContext)
				.then(this.successHandler.onAuthenticationSuccess(webFilterExchange, authentication))
				.subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
	}

	private Mono<Void> onAuthenticationFailure(AuthenticationException exception, WebFilterExchange webFilterExchange) {
		return Mono.justOrEmpty(this.failureHandler).switchIfEmpty(Mono.defer(() -> {
			this.logger.error("Switch User failed", exception);
			return Mono.error(exception);
		})).flatMap((failureHandler) -> failureHandler.onAuthenticationFailure(webFilterExchange, exception));
	}

	private Authentication createSwitchUserToken(UserDetails targetUser, Authentication currentAuthentication) {
		final Optional<Authentication> sourceAuthentication = extractSourceAuthentication(currentAuthentication);

		if (sourceAuthentication.isPresent()) {
			// SEC-1763. Check first if we are already switched.
			this.logger.info("Found original switch user granted authority [" + sourceAuthentication.get() + "]");
			currentAuthentication = sourceAuthentication.get();
		}

		final GrantedAuthority switchAuthority = new SwitchUserGrantedAuthority(ROLE_PREVIOUS_ADMINISTRATOR,
				currentAuthentication);
		final Collection<? extends GrantedAuthority> targetUserAuthorities = targetUser.getAuthorities();

		final List<GrantedAuthority> extendedTargetUserAuthorities = new ArrayList<>(targetUserAuthorities);
		extendedTargetUserAuthorities.add(switchAuthority);

		return new UsernamePasswordAuthenticationToken(targetUser, targetUser.getPassword(),
				extendedTargetUserAuthorities);
	}

	/**
	 * Find the original <code>Authentication</code> object from the current user's
	 * granted authorities. A successfully switched user should have a
	 * <code>SwitchUserGrantedAuthority</code> that contains the original source user
	 * <code>Authentication</code> object.
	 * @param currentAuthentication The current <code>Authentication</code> object
	 * @return The source user <code>Authentication</code> object or
	 * <code>Optional.empty</code> otherwise.
	 */
	private Optional<Authentication> extractSourceAuthentication(Authentication currentAuthentication) {
		// iterate over granted authorities and find the 'switch user' authority
		for (GrantedAuthority authority : currentAuthentication.getAuthorities()) {
			if (authority instanceof SwitchUserGrantedAuthority) {
				final SwitchUserGrantedAuthority switchAuthority = (SwitchUserGrantedAuthority) authority;
				return Optional.of(switchAuthority.getSource());
			}
		}
		return Optional.empty();
	}

	private static ServerWebExchangeMatcher createMatcher(String pattern) {
		return ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, pattern);
	}

	private AuthenticationCredentialsNotFoundException noCurrentUserException() {
		return new AuthenticationCredentialsNotFoundException("No current user associated with this request");
	}

	private AuthenticationCredentialsNotFoundException noOriginalAuthenticationException() {
		return new AuthenticationCredentialsNotFoundException("Could not find original Authentication object");
	}

	private AuthenticationCredentialsNotFoundException noTargetAuthenticationException() {
		return new AuthenticationCredentialsNotFoundException("No target user for the given username");
	}

	/**
	 * Sets the repository for persisting the SecurityContext. Default is
	 * {@link WebSessionServerSecurityContextRepository}
	 * @param securityContextRepository the repository to use
	 */
	public void setSecurityContextRepository(ServerSecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	/**
	 * Set the URL to respond to exit user processing. This is a shortcut for *
	 * {@link #setExitUserMatcher(ServerWebExchangeMatcher)}
	 * @param exitUserUrl The exit user URL.
	 */
	public void setExitUserUrl(String exitUserUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(exitUserUrl),
				"exitUserUrl cannot be empty and must be a valid redirect URL");
		this.exitUserMatcher = createMatcher(exitUserUrl);
	}

	/**
	 * Set the matcher to respond to exit user processing.
	 * @param exitUserMatcher The exit matcher to use
	 */
	public void setExitUserMatcher(ServerWebExchangeMatcher exitUserMatcher) {
		Assert.notNull(exitUserMatcher, "exitUserMatcher cannot be null");
		this.exitUserMatcher = exitUserMatcher;
	}

	/**
	 * Set the URL to respond to switch user processing. This is a shortcut for
	 * {@link #setSwitchUserMatcher(ServerWebExchangeMatcher)}
	 * @param switchUserUrl The switch user URL.
	 */
	public void setSwitchUserUrl(String switchUserUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(switchUserUrl),
				"switchUserUrl cannot be empty and must be a valid redirect URL");
		this.switchUserMatcher = createMatcher(switchUserUrl);
	}

	/**
	 * Set the matcher to respond to switch user processing.
	 * @param switchUserMatcher The switch user matcher.
	 */
	public void setSwitchUserMatcher(ServerWebExchangeMatcher switchUserMatcher) {
		Assert.notNull(switchUserMatcher, "switchUserMatcher cannot be null");
		this.switchUserMatcher = switchUserMatcher;
	}

	private static class SwitchUserAuthenticationException extends RuntimeException {

		SwitchUserAuthenticationException(AuthenticationException exception) {
			super(exception);
		}

	}

}
