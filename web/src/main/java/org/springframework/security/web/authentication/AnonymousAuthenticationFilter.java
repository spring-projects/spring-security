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

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.List;
import java.util.function.Supplier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.util.function.SingletonSupplier;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Detects if there is no {@code Authentication} object in the
 * {@code SecurityContextHolder}, and populates it with one if needed.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author Evgeniy Cheban
 */
public class AnonymousAuthenticationFilter extends GenericFilterBean implements InitializingBean {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private String key;

	private Object principal;

	private List<GrantedAuthority> authorities;

	/**
	 * Creates a filter with a principal named "anonymousUser" and the single authority
	 * "ROLE_ANONYMOUS".
	 * @param key the key to identify tokens created by this filter
	 */
	public AnonymousAuthenticationFilter(String key) {
		this(key, "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	/**
	 * @param key key the key to identify tokens created by this filter
	 * @param principal the principal which will be used to represent anonymous users
	 * @param authorities the authority list for anonymous users
	 */
	public AnonymousAuthenticationFilter(String key, Object principal, List<GrantedAuthority> authorities) {
		Assert.hasLength(key, "key cannot be null or empty");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
		this.key = key;
		this.principal = principal;
		this.authorities = authorities;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.hasLength(this.key, "key must have length");
		Assert.notNull(this.principal, "Anonymous authentication principal must be set");
		Assert.notNull(this.authorities, "Anonymous authorities must be set");
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		Supplier<SecurityContext> deferredContext = this.securityContextHolderStrategy.getDeferredContext();
		this.securityContextHolderStrategy
				.setDeferredContext(defaultWithAnonymous((HttpServletRequest) req, deferredContext));
		chain.doFilter(req, res);
	}

	private Supplier<SecurityContext> defaultWithAnonymous(HttpServletRequest request,
			Supplier<SecurityContext> currentDeferredContext) {
		return SingletonSupplier.of(() -> {
			SecurityContext currentContext = currentDeferredContext.get();
			return defaultWithAnonymous(request, currentContext);
		});
	}

	private SecurityContext defaultWithAnonymous(HttpServletRequest request, SecurityContext currentContext) {
		Authentication currentAuthentication = currentContext.getAuthentication();
		if (currentAuthentication == null) {
			Authentication anonymous = createAuthentication(request);
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.of(() -> "Set SecurityContextHolder to " + anonymous));
			}
			else {
				this.logger.debug("Set SecurityContextHolder to anonymous SecurityContext");
			}
			SecurityContext anonymousContext = this.securityContextHolderStrategy.createEmptyContext();
			anonymousContext.setAuthentication(anonymous);
			return anonymousContext;
		}
		else {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.of(() -> "Did not set SecurityContextHolder since already authenticated "
						+ currentAuthentication));
			}
		}
		return currentContext;
	}

	protected Authentication createAuthentication(HttpServletRequest request) {
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(this.key, this.principal,
				this.authorities);
		token.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return token;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
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

	public Object getPrincipal() {
		return this.principal;
	}

	public List<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

}
