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

package org.springframework.security.oauth2.jwt;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class ReactiveRemoteJWKSourceTests {
	@Mock
	private JWKMatcher matcher;

	private ReactiveRemoteJWKSource source;

	private JWKSelector selector;

	private MockWebServer server;

	private String keys = "{\n"
			+ "    \"keys\": [\n"
			+ "        {\n"
			+ "            \"alg\": \"RS256\", \n"
			+ "            \"e\": \"AQAB\", \n"
			+ "            \"kid\": \"1923397381d9574bb873202a90c32b7ceeaed027\", \n"
			+ "            \"kty\": \"RSA\", \n"
			+ "            \"n\": \"m4I5Dk5GnbzzUtqaljDVbpMONi1JLNJ8ZuXE8VvjCAVebDg5vTYhQ33jUwGgbn1wFmytUMgMmvK8A8Gpshl0sO2GBIZoh6_pwLrk657ZEtv-hx9fYKnzwyrfHqxtSswMAyr7XtKl8Ha1I03uFMSaYaaBTwVXCHByhzr4PVXfKAYJNbbcteUZfE8ODlBQkjQLI0IB78Nu8XIRrdzTF_5LCuM6rLUNtX6_KdzPpeX9KEtB7OBAfkdZEtBzGI-aYNLtIaL4qO6cVxBeVDLMoj9kVsRPylrwhEFQcGOjtJhwJwXFzTMZVhkiLFCHxZkkjoMrK5osSRlhduuGI9ot8XTUKQ\", \n"
			+ "            \"use\": \"sig\"\n"
			+ "        }, \n"
			+ "        {\n"
			+ "            \"alg\": \"RS256\", \n"
			+ "            \"e\": \"AQAB\", \n"
			+ "            \"kid\": \"7ddf54d3032d1f0d48c3618892ca74c1ac30ad77\", \n"
			+ "            \"kty\": \"RSA\", \n"
			+ "            \"n\": \"yLlYyux949b7qS-DdqTNjdZb4NtqiNH-Jt7DtRxmfW9XZLOQ6Q2NYgmPe9hyy5GHG7W3zsd6Q-rzq5eGRNEUx1767K1dS5PtkVWPiPG_M7rDqCu3HsLmKQKhRjHYaCWl5NuiMB5mXoPhSwrHd2yeGE7QHIV7_CiQFc1xQsXeiC-nTeJohJO3HI97w0GXE8pHspLYq9oG87f5IHxFr89abmwRug-D7QWQyW5b4doe4ZL-52J-8WHd52kGrGfu4QyV83oAad3I_9Q-yiWOXUr_0GIrzz4_-u5HgqYexnodFhZZSaKuRSg_b5qCnPhW8gBDLAHkmQzQMaWsN14L0pokbQ\", \n"
			+ "            \"use\": \"sig\"\n"
			+ "        }\n"
			+ "    ]\n"
			+ "}\n";


	private String keys2 = "{\n"
			+ "    \"keys\": [\n"
			+ "        {\n"
			+ "            \"alg\": \"RS256\", \n"
			+ "            \"e\": \"AQAB\", \n"
			+ "            \"kid\": \"rotated\", \n"
			+ "            \"kty\": \"RSA\", \n"
			+ "            \"n\": \"m4I5Dk5GnbzzUtqaljDVbpMONi1JLNJ8ZuXE8VvjCAVebDg5vTYhQ33jUwGgbn1wFmytUMgMmvK8A8Gpshl0sO2GBIZoh6_pwLrk657ZEtv-hx9fYKnzwyrfHqxtSswMAyr7XtKl8Ha1I03uFMSaYaaBTwVXCHByhzr4PVXfKAYJNbbcteUZfE8ODlBQkjQLI0IB78Nu8XIRrdzTF_5LCuM6rLUNtX6_KdzPpeX9KEtB7OBAfkdZEtBzGI-aYNLtIaL4qO6cVxBeVDLMoj9kVsRPylrwhEFQcGOjtJhwJwXFzTMZVhkiLFCHxZkkjoMrK5osSRlhduuGI9ot8XTUKQ\", \n"
			+ "            \"use\": \"sig\"\n"
			+ "        }\n"
			+ "    ]\n"
			+ "}\n";

	@Before
	public void setup() {
		this.server = new MockWebServer();
		this.source = new ReactiveRemoteJWKSource(this.server.url("/").toString());

		this.server.enqueue(new MockResponse().setBody(this.keys));
		this.selector = new JWKSelector(this.matcher);
	}

	@Test
	public void getWhenMultipleRequestThenCached() {
		when(this.matcher.matches(any())).thenReturn(true);

		this.source.get(this.selector).block();
		this.source.get(this.selector).block();

		assertThat(this.server.getRequestCount()).isEqualTo(1);
	}

	@Test
	public void getWhenMatchThenCreatesKeys() {
		when(this.matcher.matches(any())).thenReturn(true);

		List<JWK> keys = this.source.get(this.selector).block();
		assertThat(keys).hasSize(2);
		JWK key1 = keys.get(0);
		assertThat(key1.getKeyID()).isEqualTo("1923397381d9574bb873202a90c32b7ceeaed027");
		assertThat(key1.getAlgorithm().getName()).isEqualTo("RS256");
		assertThat(key1.getKeyType()).isEqualTo(KeyType.RSA);
		assertThat(key1.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);

		JWK key2 = keys.get(1);
		assertThat(key2.getKeyID()).isEqualTo("7ddf54d3032d1f0d48c3618892ca74c1ac30ad77");
		assertThat(key2.getAlgorithm().getName()).isEqualTo("RS256");
		assertThat(key2.getKeyType()).isEqualTo(KeyType.RSA);
		assertThat(key2.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
	}

	@Test
	public void getWhenNoMatchAndNoKeyIdThenEmpty() {
		when(this.matcher.matches(any())).thenReturn(false);
		when(this.matcher.getKeyIDs()).thenReturn(Collections.emptySet());

		assertThat(this.source.get(this.selector).block()).isEmpty();
	}

	@Test
	public void getWhenNoMatchAndKeyIdNotMatchThenRefreshAndFoundThenFound() {
		this.server.enqueue(new MockResponse().setBody(this.keys2));
		when(this.matcher.matches(any())).thenReturn(false, false, true);
		when(this.matcher.getKeyIDs()).thenReturn(Collections.singleton("rotated"));

		List<JWK> keys = this.source.get(this.selector).block();

		assertThat(keys).hasSize(1);
		assertThat(keys.get(0).getKeyID()).isEqualTo("rotated");
	}

	@Test
	public void getWhenNoMatchAndKeyIdNotMatchThenRefreshAndNotFoundThenEmpty() {
		this.server.enqueue(new MockResponse().setBody(this.keys2));
		when(this.matcher.matches(any())).thenReturn(false, false, false);
		when(this.matcher.getKeyIDs()).thenReturn(Collections.singleton("rotated"));

		List<JWK> keys = this.source.get(this.selector).block();

		assertThat(keys).isEmpty();
	}

	@Test
	public void getWhenNoMatchAndKeyIdMatchThenEmpty() {
		when(this.matcher.matches(any())).thenReturn(false);
		when(this.matcher.getKeyIDs()).thenReturn(Collections.singleton("7ddf54d3032d1f0d48c3618892ca74c1ac30ad77"));

		assertThat(this.source.get(this.selector).block()).isEmpty();
	}
}
