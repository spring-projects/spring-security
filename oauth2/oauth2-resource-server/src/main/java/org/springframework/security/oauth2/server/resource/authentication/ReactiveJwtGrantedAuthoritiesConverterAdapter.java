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

import reactor.core.publisher.Flux;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * Adapts a {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;} to
 * a {@link Converter Converter&lt;Jwt, Flux&lt;GrantedAuthority&gt;&gt;}.
 * <p>
 * Make sure the {@link Converter Converter&lt;Jwt,
 * Collection&lt;GrantedAuthority&gt;&gt;} being adapted is non-blocking.
 * </p>
 *
 * @author Eric Deandrea
 * @since 5.2
 * @see JwtGrantedAuthoritiesConverter
 */
public final class ReactiveJwtGrantedAuthoritiesConverterAdapter implements Converter<Jwt, Flux<GrantedAuthority>> {

	private final Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter;

	public ReactiveJwtGrantedAuthoritiesConverterAdapter(
			Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter) {
		Assert.notNull(grantedAuthoritiesConverter, "grantedAuthoritiesConverter cannot be null");
		this.grantedAuthoritiesConverter = grantedAuthoritiesConverter;
	}

	@Override
	public Flux<GrantedAuthority> convert(Jwt jwt) {
		return Flux.fromIterable(this.grantedAuthoritiesConverter.convert(jwt));
	}

}
