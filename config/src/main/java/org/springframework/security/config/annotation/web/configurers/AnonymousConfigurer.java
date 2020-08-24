/*
 * Copyright 2002-2013 the original author or authors.
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

import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * Configures Anonymous authentication (i.e. populate an {@link Authentication} that
 * represents an anonymous user instead of having a null value) for an
 * {@link HttpSecurity}. Specifically this will configure an
 * {@link AnonymousAuthenticationFilter} and an {@link AnonymousAuthenticationProvider}.
 * All properties have reasonable defaults, so no additional configuration is required
 * other than applying this {@link SecurityConfigurer}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class AnonymousConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<AnonymousConfigurer<H>, H> {

	private String key;

	private AuthenticationProvider authenticationProvider;

	private AnonymousAuthenticationFilter authenticationFilter;

	private Object principal = "anonymousUser";

	private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");

	/**
	 * Creates a new instance
	 * @see HttpSecurity#anonymous()
	 */
	public AnonymousConfigurer() {
	}

	/**
	 * Sets the key to identify tokens created for anonymous authentication. Default is a
	 * secure randomly generated key.
	 * @param key the key to identify tokens created for anonymous authentication. Default
	 * is a secure randomly generated key.
	 * @return the {@link AnonymousConfigurer} for further customization of anonymous
	 * authentication
	 */
	public AnonymousConfigurer<H> key(String key) {
		this.key = key;
		return this;
	}

	/**
	 * Sets the principal for {@link Authentication} objects of anonymous users
	 * @param principal used for the {@link Authentication} object of anonymous users
	 * @return the {@link AnonymousConfigurer} for further customization of anonymous
	 * authentication
	 */
	public AnonymousConfigurer<H> principal(Object principal) {
		this.principal = principal;
		return this;
	}

	/**
	 * Sets the {@link org.springframework.security.core.Authentication#getAuthorities()}
	 * for anonymous users
	 * @param authorities Sets the
	 * {@link org.springframework.security.core.Authentication#getAuthorities()} for
	 * anonymous users
	 * @return the {@link AnonymousConfigurer} for further customization of anonymous
	 * authentication
	 */
	public AnonymousConfigurer<H> authorities(List<GrantedAuthority> authorities) {
		this.authorities = authorities;
		return this;
	}

	/**
	 * Sets the {@link org.springframework.security.core.Authentication#getAuthorities()}
	 * for anonymous users
	 * @param authorities Sets the
	 * {@link org.springframework.security.core.Authentication#getAuthorities()} for
	 * anonymous users (i.e. "ROLE_ANONYMOUS")
	 * @return the {@link AnonymousConfigurer} for further customization of anonymous
	 * authentication
	 */
	public AnonymousConfigurer<H> authorities(String... authorities) {
		return authorities(AuthorityUtils.createAuthorityList(authorities));
	}

	/**
	 * Sets the {@link AuthenticationProvider} used to validate an anonymous user. If this
	 * is set, no attributes on the {@link AnonymousConfigurer} will be set on the
	 * {@link AuthenticationProvider}.
	 * @param authenticationProvider the {@link AuthenticationProvider} used to validate
	 * an anonymous user. Default is {@link AnonymousAuthenticationProvider}
	 * @return the {@link AnonymousConfigurer} for further customization of anonymous
	 * authentication
	 */
	public AnonymousConfigurer<H> authenticationProvider(AuthenticationProvider authenticationProvider) {
		this.authenticationProvider = authenticationProvider;
		return this;
	}

	/**
	 * Sets the {@link AnonymousAuthenticationFilter} used to populate an anonymous user.
	 * If this is set, no attributes on the {@link AnonymousConfigurer} will be set on the
	 * {@link AnonymousAuthenticationFilter}.
	 * @param authenticationFilter the {@link AnonymousAuthenticationFilter} used to
	 * populate an anonymous user.
	 * @return the {@link AnonymousConfigurer} for further customization of anonymous
	 * authentication
	 */
	public AnonymousConfigurer<H> authenticationFilter(AnonymousAuthenticationFilter authenticationFilter) {
		this.authenticationFilter = authenticationFilter;
		return this;
	}

	@Override
	public void init(H http) {
		if (this.authenticationProvider == null) {
			this.authenticationProvider = new AnonymousAuthenticationProvider(getKey());
		}
		if (this.authenticationFilter == null) {
			this.authenticationFilter = new AnonymousAuthenticationFilter(getKey(), this.principal, this.authorities);
		}
		this.authenticationProvider = postProcess(this.authenticationProvider);
		http.authenticationProvider(this.authenticationProvider);
	}

	@Override
	public void configure(H http) {
		this.authenticationFilter.afterPropertiesSet();
		http.addFilter(this.authenticationFilter);
	}

	private String getKey() {
		if (this.key == null) {
			this.key = UUID.randomUUID().toString();
		}
		return this.key;
	}

}
