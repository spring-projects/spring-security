/*
 * Copyright 2002-2023 the original author or authors.
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

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;

/**
 * Reactive version of {@link JwtAuthenticationConverter} for converting a {@link Jwt} to
 * a {@link AbstractAuthenticationToken Mono&lt;AbstractAuthenticationToken&gt;}.
 *
 * @author Eric Deandrea
 * @author Marcus Kainth
 * @since 5.2
 */
public final class ReactiveJwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

	private Converter<Jwt, Flux<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new ReactiveJwtGrantedAuthoritiesConverterAdapter(
			new JwtGrantedAuthoritiesConverter());

	private String principalClaimName = JwtClaimNames.SUB;

	@Override
	public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
		// @formatter:off
		return this.jwtGrantedAuthoritiesConverter.convert(jwt)
				.collectList()
				.map((authorities) -> {
					String principalName = jwt.getClaimAsString(this.principalClaimName);
					return new JwtAuthenticationToken(jwt, authorities, principalName);
				});
		// @formatter:on
	}

	/**
	 * Sets the {@link Converter Converter&lt;Jwt, Flux&lt;GrantedAuthority&gt;&gt;} to
	 * use. Defaults to a reactive {@link JwtGrantedAuthoritiesConverter}.
	 * @param jwtGrantedAuthoritiesConverter The converter
	 * @see JwtGrantedAuthoritiesConverter
	 */
	public void setJwtGrantedAuthoritiesConverter(
			Converter<Jwt, Flux<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
		Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
		this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
	}

	/**
	 * Sets the principal claim name. Defaults to {@link JwtClaimNames#SUB}.
	 * @param principalClaimName The principal claim name
	 * @since 6.1
	 */
	public void setPrincipalClaimName(String principalClaimName) {
		Assert.hasText(principalClaimName, "principalClaimName cannot be empty");
		this.principalClaimName = principalClaimName;
	}

}
