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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;

/**
 * @author Rob Winch
 * @author Josh Cummings
 * @author Evgeniy Cheban
 * @since 5.1
 */
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
	private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter
			= new JwtGrantedAuthoritiesConverter();

	private String principalClaimName;

	@Override
	public final AbstractAuthenticationToken convert(Jwt jwt) {
		Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
		if (this.principalClaimName == null) {
			return new JwtAuthenticationToken(jwt, authorities);
		}

		String name = jwt.getClaim(this.principalClaimName);
		return new JwtAuthenticationToken(jwt, authorities, name);
	}

	/**
	 * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a {@link Jwt}
	 *
	 * @param jwt The token
	 * @return The collection of {@link GrantedAuthority}s found on the token
	 * @deprecated Since 5.2. Use your own custom converter instead
	 * @see JwtGrantedAuthoritiesConverter
	 * @see #setJwtGrantedAuthoritiesConverter(Converter)
	 */
	@Deprecated
	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		return this.jwtGrantedAuthoritiesConverter.convert(jwt);
	}

	/**
	 * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;} to use.
	 * Defaults to {@link JwtGrantedAuthoritiesConverter}.
	 *
	 * @param jwtGrantedAuthoritiesConverter The converter
	 * @since 5.2
	 * @see JwtGrantedAuthoritiesConverter
	 */
	public void setJwtGrantedAuthoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
		Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
		this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
	}

	/**
	 * Sets the principal claim name.
	 * Defaults to {@link JwtClaimNames#SUB}.
	 *
	 * @param principalClaimName The principal claim name
	 * @since 5.4
	 */
	public void setPrincipalClaimName(String principalClaimName) {
		Assert.hasText(principalClaimName, "principalClaimName cannot be empty");
		this.principalClaimName = principalClaimName;
	}
}
