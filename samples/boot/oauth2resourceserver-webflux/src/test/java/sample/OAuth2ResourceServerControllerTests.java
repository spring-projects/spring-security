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

package sample;

import org.junit.Test;
import org.junit.runner.RunWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@WebFluxTest(OAuth2ResourceServerController.class)
@Import(SecurityConfig.class)
public class OAuth2ResourceServerControllerTests {

		@Autowired
		WebTestClient rest;

		@MockBean
		ReactiveJwtDecoder jwtDecoder;

		@Test
		public void indexGreetsAuthenticatedUser() {
			this.rest.mutateWith(mockJwt(jwt -> jwt.subject("test-subject")))
					.get().uri("/").exchange()
					.expectBody(String.class).isEqualTo("Hello, test-subject!");
		}

		@Test
		public void messageCanBeReadWithScopeMessageReadAuthority() {
			this.rest.mutateWith(mockJwt(jwt -> jwt.claim("scope", "message:read")))
					.get().uri("/message").exchange()
					.expectBody(String.class).isEqualTo("secret message");

			this.rest.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("SCOPE_message:read")))
					.get().uri("/message").exchange()
					.expectBody(String.class).isEqualTo("secret message");
		}

		@Test
		public void messageCanNotBeReadWithoutScopeMessageReadAuthority() {
			this.rest.mutateWith(mockJwt())
					.get().uri("/message").exchange()
					.expectStatus().isForbidden();
		}

		@Test
		public void messageCanNotBeCreatedWithoutAnyScope() {
			Jwt jwt = jwt().claim("scope", "").build();
			when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));
			this.rest.post().uri("/message")
					.headers(headers -> headers.setBearerAuth(jwt.getTokenValue()))
					.syncBody("Hello message").exchange()
					.expectStatus().isForbidden();
		}

		@Test
		public void messageCanNotBeCreatedWithScopeMessageReadAuthority() {
			Jwt jwt = jwt().claim("scope", "message:read").build();
			when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));
			this.rest.post().uri("/message")
					.headers(headers -> headers.setBearerAuth(jwt.getTokenValue()))
					.syncBody("Hello message").exchange()
					.expectStatus().isForbidden();
		}

		@Test
		public void messageCanBeCreatedWithScopeMessageWriteAuthority() {
			Jwt jwt = jwt().claim("scope", "message:write").build();
			when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));
			this.rest.post().uri("/message")
					.headers(headers -> headers.setBearerAuth(jwt.getTokenValue()))
					.syncBody("Hello message").exchange()
					.expectStatus().isOk()
					.expectBody(String.class).isEqualTo("Message was created. Content: Hello message");
		}

		private Jwt.Builder jwt() {
			return Jwt.withTokenValue("token").header("alg", "none");
		}
}
