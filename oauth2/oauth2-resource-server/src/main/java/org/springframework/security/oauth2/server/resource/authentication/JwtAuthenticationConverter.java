/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * Builds a {@link JwtAuthenticationToken} from a {@link Jwt}
 * 
 * @author Rob Winch
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
	private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter;

	/**
	 * @param jwtGrantedAuthoritiesConverter delegate responsible for extracting {@link GrantedAuthority authorities} from a {@link Jwt}
	 */
	@Autowired
	public JwtAuthenticationConverter(
			final Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
		this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
	}

	/**
	 * Defaults {@link GrantedAuthority authorities} converter to a reasonable one.
	 * @see JwtScopesGrantedAuthoritiesConverter
	 */
	public JwtAuthenticationConverter() {
		this(new JwtScopesGrantedAuthoritiesConverter());
	}

	@Override
	public final AbstractAuthenticationToken convert(final Jwt jwt) {
		final Collection<GrantedAuthority> authorities = this.jwtGrantedAuthoritiesConverter.convert(jwt);
		return new JwtAuthenticationToken(jwt, authorities);
	}

	/**
	 * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a {@link Jwt}
	 *
	 * @param jwt The token
	 * @return The collection of {@link GrantedAuthority}s found on the token
	 * @deprecated Since 5.2. Use your own custom converter instead
	 * @see JwtScopesGrantedAuthoritiesConverter
	 * @see #setJwtGrantedAuthoritiesConverter(Converter)
	 */
	@Deprecated
	protected Collection<GrantedAuthority> extractAuthorities(final Jwt jwt) {
		return this.jwtGrantedAuthoritiesConverter.convert(jwt);
	}

	/**
	 * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;} to use.
	 * Defaults to {@link JwtScopesGrantedAuthoritiesConverter}.
	 *
	 * @param jwtGrantedAuthoritiesConverter The converter
	 * @since 5.2
	 * @see JwtScopesGrantedAuthoritiesConverter
	 */
	public void setJwtGrantedAuthoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
		Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
		this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
	}
}
