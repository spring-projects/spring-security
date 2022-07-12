/*
 * Copyright 2002-2022 the original author or authors.
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

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * JWT {@link OAuth2AuthorizationService}
 *
 * @author xuxiaowei
 * @since 5.8.0
 */
public class OAuth2AuthorizationServiceJwtAuthenticationConverter
		implements Converter<Jwt, AbstractAuthenticationToken> {

	private final OAuth2AuthorizationService authorizationService;

	public OAuth2AuthorizationServiceJwtAuthenticationConverter(
			@NonNull OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

	private String principalClaimName = JwtClaimNames.SUB;

	@Override
	public final AbstractAuthenticationToken convert(@NonNull Jwt jwt) {

		String tokenValue = jwt.getTokenValue();
		OAuth2Authorization authorization = authorizationService.findByToken(tokenValue, OAuth2TokenType.ACCESS_TOKEN);
		if (authorization == null) {
			throw new InvalidBearerTokenException(tokenValue + " not found in OAuth2AuthorizationService");
		}

		Collection<GrantedAuthority> authorities = this.jwtGrantedAuthoritiesConverter.convert(jwt);

		String principalClaimValue = jwt.getClaimAsString(this.principalClaimName);
		return new JwtAuthenticationToken(jwt, authorities, principalClaimValue);
	}

	public void setJwtGrantedAuthoritiesConverter(
			Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
		Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
		this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
	}

	public void setPrincipalClaimName(String principalClaimName) {
		Assert.hasText(principalClaimName, "principalClaimName cannot be empty");
		this.principalClaimName = principalClaimName;
	}

}
