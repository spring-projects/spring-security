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

package org.springframework.security.oauth2.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;

/**
 * Test values of {@link OAuth2AuthenticatedPrincipal}s
 *
 * @author Josh Cummings
 */
public class TestOAuth2AuthenticatedPrincipals {
	public static OAuth2AuthenticatedPrincipal active() {
		return active(attributes -> {});
	}

	public static OAuth2AuthenticatedPrincipal active(Consumer<Map<String, Object>> attributesConsumer) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2IntrospectionClaimNames.ACTIVE, true);
		attributes.put(OAuth2IntrospectionClaimNames.AUDIENCE, Arrays.asList("https://protected.example.net/resource"));
		attributes.put(OAuth2IntrospectionClaimNames.CLIENT_ID, "l238j323ds-23ij4");
		attributes.put(OAuth2IntrospectionClaimNames.EXPIRES_AT, Instant.ofEpochSecond(1419356238));
		attributes.put(OAuth2IntrospectionClaimNames.NOT_BEFORE, Instant.ofEpochSecond(29348723984L));
		attributes.put(OAuth2IntrospectionClaimNames.ISSUER, url("https://server.example.com/"));
		attributes.put(OAuth2IntrospectionClaimNames.SCOPE, Arrays.asList("read", "write", "dolphin"));
		attributes.put(OAuth2IntrospectionClaimNames.SUBJECT, "Z5O3upPC88QrAjx00dis");
		attributes.put(OAuth2IntrospectionClaimNames.USERNAME, "jdoe");
		attributesConsumer.accept(attributes);

		Collection<GrantedAuthority> authorities =
				Arrays.asList(new SimpleGrantedAuthority("SCOPE_read"),
						new SimpleGrantedAuthority("SCOPE_write"), new SimpleGrantedAuthority("SCOPE_dolphin"));
		return new OAuth2IntrospectionAuthenticatedPrincipal(attributes, authorities);
	}

	private static URL url(String url) {
		try {
			return new URL(url);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}
}
