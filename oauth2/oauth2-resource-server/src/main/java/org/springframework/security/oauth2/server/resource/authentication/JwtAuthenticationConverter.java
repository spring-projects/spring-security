/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;

/**
 * @author Rob Winch
 * @author Josh Cummings
 * @author Evgeniy Cheban
 * @author Olivier Antoine
 * @author Andrey Litvitski
 * @since 5.1
 */
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	private Converter<Jwt, OAuth2AuthenticatedPrincipal> jwtPrincipalConverter;
	private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

	private String principalClaimName = JwtClaimNames.SUB;

	@Override
	public final AbstractAuthenticationToken convert(Jwt jwt) {
		Collection<GrantedAuthority> authorities = this.jwtGrantedAuthoritiesConverter.convert(jwt);

		if (this.jwtPrincipalConverter == null) {
			String principalClaimValue = jwt.getClaimAsString(this.principalClaimName);
			return new JwtAuthenticationToken(jwt, authorities, principalClaimValue);
		} else {
			OAuth2AuthenticatedPrincipal principal = this.jwtPrincipalConverter.convert(jwt);
			authorities.addAll(principal.getAuthorities());
			return new JwtAuthenticationToken(jwt, principal, authorities);
		}
	}

	/**
	 * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;OAuth2AuthenticatedPrincipal&gt;&gt;}
	 * to use.
	 * @param jwtPrincipalConverter The converter
	 * @since 6.5.0
	 */
	public void setJwtPrincipalConverter(
			Converter<Jwt, OAuth2AuthenticatedPrincipal> jwtPrincipalConverter) {
		Assert.notNull(jwtPrincipalConverter, "jwtPrincipalConverter cannot be null");
		this.jwtPrincipalConverter = jwtPrincipalConverter;
	}

	/**
	 * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;}
	 * to use. Defaults to {@link JwtGrantedAuthoritiesConverter}.
	 * @param jwtGrantedAuthoritiesConverter The converter
	 * @since 5.2
	 * @see JwtGrantedAuthoritiesConverter
	 */
	public void setJwtGrantedAuthoritiesConverter(
			Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
		Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
		this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
	}

	/**
	 * Sets the principal claim name. Defaults to {@link JwtClaimNames#SUB}.
	 * @param principalClaimName The principal claim name
	 * @since 5.4
	 */
	public void setPrincipalClaimName(String principalClaimName) {
		Assert.hasText(principalClaimName, "principalClaimName cannot be empty");
		this.principalClaimName = principalClaimName;
	}

}
