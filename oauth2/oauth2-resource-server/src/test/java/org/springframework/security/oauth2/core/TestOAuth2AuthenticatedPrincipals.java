/*
 * Copyright 2002-2021 the original author or authors.
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

/**
 * Test values of {@link OAuth2AuthenticatedPrincipal}s
 *
 * @author Josh Cummings
 */
public final class TestOAuth2AuthenticatedPrincipals {

	private TestOAuth2AuthenticatedPrincipals() {
	}

	public static OAuth2AuthenticatedPrincipal active() {
		return active((attributes) -> {
		});
	}

	public static OAuth2AuthenticatedPrincipal active(Consumer<Map<String, Object>> attributesConsumer) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2TokenIntrospectionClaimNames.ACTIVE, true);
		attributes.put(OAuth2TokenIntrospectionClaimNames.AUD, Arrays.asList("https://protected.example.net/resource"));
		attributes.put(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, "l238j323ds-23ij4");
		attributes.put(OAuth2TokenIntrospectionClaimNames.EXP, Instant.ofEpochSecond(1419356238));
		attributes.put(OAuth2TokenIntrospectionClaimNames.NBF, Instant.ofEpochSecond(29348723984L));
		attributes.put(OAuth2TokenIntrospectionClaimNames.ISS, url("https://server.example.com/"));
		attributes.put(OAuth2TokenIntrospectionClaimNames.SCOPE, Arrays.asList("read", "write", "dolphin"));
		attributes.put(OAuth2TokenIntrospectionClaimNames.SUB, "Z5O3upPC88QrAjx00dis");
		attributes.put(OAuth2TokenIntrospectionClaimNames.USERNAME, "jdoe");
		attributesConsumer.accept(attributes);
		Collection<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("SCOPE_read"),
				new SimpleGrantedAuthority("SCOPE_write"), new SimpleGrantedAuthority("SCOPE_dolphin"));
		return new OAuth2IntrospectionAuthenticatedPrincipal(attributes, authorities);
	}

	private static URL url(String url) {
		try {
			return new URL(url);
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

}
