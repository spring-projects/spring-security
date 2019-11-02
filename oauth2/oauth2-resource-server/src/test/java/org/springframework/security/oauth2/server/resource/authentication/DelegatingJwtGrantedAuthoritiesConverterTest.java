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

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.Test;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for verifying {@link DelegatingJwtGrantedAuthoritiesConverter}
 *
 * @author Laszlo Stahorszki
 */
public class DelegatingJwtGrantedAuthoritiesConverterTest {

	@Test
	public void convertNoConverters() {
		DelegatingJwtGrantedAuthoritiesConverter subject = new DelegatingJwtGrantedAuthoritiesConverter();

		assertThat(subject.convert(Jwt.withTokenValue("some-token-value")
				.header("header", "value")
				.claim("claim", "value")
				.build())).isEmpty();
	}

	@Test
	public void convert() {
		DelegatingJwtGrantedAuthoritiesConverter subject = new DelegatingJwtGrantedAuthoritiesConverter(((source) ->
				Collections.singletonList(new SimpleGrantedAuthority(source.getClaim("claim")))));

		assertThat(subject.convert(Jwt.withTokenValue("some-token-value")
				.header("header", "value")
				.claim("claim", "value")
				.build())).containsExactlyInAnyOrder(new SimpleGrantedAuthority("value"));
	}

	@Test
	public void convertMultipleConverters() {
		DelegatingJwtGrantedAuthoritiesConverter subject = new DelegatingJwtGrantedAuthoritiesConverter(
				(source) -> Collections.singletonList(new SimpleGrantedAuthority(source.getClaim("claim"))),
				(source) -> Arrays.stream(source.getHeaders().entrySet().toArray(new Map.Entry[]{}))
						.map(Map.Entry::getValue)
						.map(Object::toString)
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList()));

		assertThat(subject.convert(Jwt.withTokenValue("some-token-value")
				.header("header", "value")
				.header("header2", "value2")
				.claim("claim", "value3")
				.build())).containsExactlyInAnyOrder(
						new SimpleGrantedAuthority("value"),
						new SimpleGrantedAuthority("value2"),
						new SimpleGrantedAuthority("value3")
		);
	}
}
