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
package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * An implementation of an {@link AbstractOAuth2TokenAuthenticationToken}
 * representing a {@link Jwt} {@code Authentication}.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see AbstractOAuth2TokenAuthenticationToken
 * @see Jwt
 */
@Transient
public class JwtAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 *
	 * @param jwt the JWT
	 */
	public JwtAuthenticationToken(Jwt jwt) {
		super(jwt);
	}

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 *
	 * @param jwt the JWT
	 * @param authorities the authorities assigned to the JWT
	 */
	public JwtAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
		super(jwt, authorities);
		this.setAuthenticated(true);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Object> getTokenAttributes() {
		return this.getToken().getClaims();
	}

	/**
	 * The {@link Jwt}'s subject, if any
	 */
	@Override
	public String getName() {
		return this.getToken().getSubject();
	}
	
	/**
	 * Helps configure a {@link JwtAuthenticationToken}
	 *
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 */
	public static class Builder<T extends Builder<T>> {

		protected Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

		protected final Jwt.Builder jwt;

		@Autowired
		public Builder(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
			this.jwt = new Jwt.Builder();
		}

		public T authoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
			return downcast();
		}

		public T token(Consumer<Jwt.Builder> jwtBuilderConsumer) {
			jwtBuilderConsumer.accept(jwt);
			return downcast();
		}

		public T name(String name) {
			jwt.subject(name);
			return downcast();
		}

		/**
		 * Shortcut to set "scope" claim with a space separated string containing provided scope collection
		 * @param scopes strings to join with spaces and set as "scope" claim
		 * @return this builder to further configure
		 */
		public T scopes(String... scopes) {
			jwt.claim("scope", Stream.of(scopes).collect(Collectors.joining(" ")));
			return downcast();
		}

		public JwtAuthenticationToken build() {
			final Jwt token = jwt.build();
			return new JwtAuthenticationToken(token, authoritiesConverter.convert(token));
		}

		@SuppressWarnings("unchecked")
		protected T downcast() {
			return (T) this;
		}
	}
}
