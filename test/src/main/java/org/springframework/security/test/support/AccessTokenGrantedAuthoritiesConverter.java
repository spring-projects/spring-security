package org.springframework.security.test.support;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

class AccessTokenGrantedAuthoritiesConverter
		implements
		Converter<OAuth2AccessToken, Collection<GrantedAuthority>> {
	@Override
	public Collection<GrantedAuthority> convert(final OAuth2AccessToken token) {
		return token.getScopes()
				.stream()
				.map(scope -> "SCOPE_" + scope)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}
}
