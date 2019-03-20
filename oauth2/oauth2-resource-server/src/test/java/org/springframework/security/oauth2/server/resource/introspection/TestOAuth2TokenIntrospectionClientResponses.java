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

package org.springframework.security.oauth2.server.resource.introspection;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ACTIVE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SCOPE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SUBJECT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.USERNAME;

public class TestOAuth2TokenIntrospectionClientResponses {
	public static Map<String, Object> active() {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(ACTIVE, true);
		attributes.put(AUDIENCE, Arrays.asList("https://protected.example.net/resource"));
		attributes.put(CLIENT_ID, "l238j323ds-23ij4");
		attributes.put(EXPIRES_AT, Instant.ofEpochSecond(1419356238));
		attributes.put(NOT_BEFORE, Instant.ofEpochSecond(29348723984L));
		attributes.put(ISSUER, url("https://server.example.com/"));
		attributes.put(SCOPE, Arrays.asList("read", "write", "dolphin"));
		attributes.put(SUBJECT, "Z5O3upPC88QrAjx00dis");
		attributes.put(USERNAME, "jdoe");
		return attributes;
	}

	private static URL url(String url) {
		try {
			return new URL(url);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}
}
