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
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

/**
 * Extracts the {@link GrantedAuthority}s from scope claims typically found in a
 * {@link Jwt}.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @author Eric Deandrea
 * @since 5.2
 */
public final class JwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
	private static final String DEFAULT_AUTHORITIES_PREFIX = "SCOPE_";

	private static final Map<String, String> WELL_KNOWN_SCOPE_CLAIM_NAMES = new HashMap<>();
	static {
		WELL_KNOWN_SCOPE_CLAIM_NAMES.put("scope", DEFAULT_AUTHORITIES_PREFIX);
		WELL_KNOWN_SCOPE_CLAIM_NAMES.put("scp", DEFAULT_AUTHORITIES_PREFIX);
	}

	private Map<String, String> authoritiesClaimNames;

	public JwtGrantedAuthoritiesConverter(Map<String, String> authoritiesClaimNames) {
		super();
		this.authoritiesClaimNames = new HashMap<>(authoritiesClaimNames);
	}

	public JwtGrantedAuthoritiesConverter() {
		this(WELL_KNOWN_SCOPE_CLAIM_NAMES);
	}

	/**
	 * Provided token claim will be scanned for authorities, in addition to already configured ones.
	 * See {@link #setAuthoritiesClaim(String, String)} to discard already configured ones.
	 *
	 * @param claimName
	 * @param prefix
	 */
	public JwtGrantedAuthoritiesConverter addAuthoritiesClaimName(String authoritiesClaimName, String prefix) {
		this.authoritiesClaimNames.put(authoritiesClaimName, prefix);
		return this;
	}

	/**
	 * Only provided token claim will be scanned for authorities. Already configured ones are discarded.
	 * See {@link #addAuthoritiesClaim(String, String)} to add a new claim (or change prefix) to already configured ones.
	 *
	 * @param claimName
	 * @param prefix
	 */
	public JwtGrantedAuthoritiesConverter setAuthoritiesClaimName(String authoritiesClaimName, String prefix) {
		this.authoritiesClaimNames.clear();
		this.authoritiesClaimNames.put(authoritiesClaimName, prefix);
		return this;
	}

	public JwtGrantedAuthoritiesConverter setAuthoritiesClaimNames(Map<String, String> authoritiesClaimNames) {
		this.authoritiesClaimNames.clear();
		this.authoritiesClaimNames.putAll(authoritiesClaimNames);
		return this;
	}

	/**
	 * Extracts the authorities
	 * @param jwt The {@link Jwt} token
	 * @return The {@link GrantedAuthority authorities} read from the token scopes
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		return authoritiesClaimNames.entrySet().stream()
				.flatMap(claim -> getAuthorities(jwt, claim.getKey()).map(claim.getValue()::concat))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

	@SuppressWarnings("unchecked")
	private Stream<String> getAuthorities(Jwt jwt, String claimName) {
		Object authorities = jwt.getClaim(claimName);
		if (authorities instanceof String) {
			if (StringUtils.hasText((String) authorities)) {
				return Stream.of(((String) authorities).split(" "));
			} else {
				return Stream.empty();
			}
		} else if (authorities instanceof Collection) {
			return ((Collection<String>) authorities).stream();
		}

		return Stream.empty();
	}
}
