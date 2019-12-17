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

package org.springframework.security.oauth2.core.web.reactive.function;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.codec.ByteBufferDecoder;
import org.springframework.core.codec.StringDecoder;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.http.codec.DecoderHttpMessageReader;
import org.springframework.http.codec.FormHttpMessageReader;
import org.springframework.http.codec.HttpMessageReader;
import org.springframework.http.codec.json.Jackson2JsonDecoder;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.client.reactive.MockClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.reactive.function.BodyExtractor;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class OAuth2BodyExtractorsTests {

	private BodyExtractor.Context context;

	private Map<String, Object> hints;

	@Before
	public void createContext() {
		final List<HttpMessageReader<?>> messageReaders = new ArrayList<>();
		messageReaders.add(new DecoderHttpMessageReader<>(new ByteBufferDecoder()));
		messageReaders.add(new DecoderHttpMessageReader<>(StringDecoder.allMimeTypes()));
		messageReaders.add(new DecoderHttpMessageReader<>(new Jackson2JsonDecoder()));
		messageReaders.add(new FormHttpMessageReader());

		this.hints = new HashMap<>();
		this.context = new BodyExtractor.Context() {
			@Override
			public List<HttpMessageReader<?>> messageReaders() {
				return messageReaders;
			}

			@Override
			public Optional<ServerHttpResponse> serverResponse() {
				return Optional.empty();
			}

			@Override
			public Map<String, Object> hints() {
				return OAuth2BodyExtractorsTests.this.hints;
			}
		};
	}

	@Test
	public void oauth2AccessTokenResponseWhenInvalidJsonThenException() {
		BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> extractor = OAuth2BodyExtractors
				.oauth2AccessTokenResponse();

		MockClientHttpResponse response = new MockClientHttpResponse(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		response.setBody("{");

		Mono<OAuth2AccessTokenResponse> result = extractor.extract(response, this.context);

		assertThatCode(result::block)
				.isInstanceOf(OAuth2AuthorizationException.class)
				.hasMessageContaining("An error occurred parsing the Access Token response");
	}

	@Test
	public void oauth2AccessTokenResponseWhenEmptyThenException() {
		BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> extractor = OAuth2BodyExtractors
				.oauth2AccessTokenResponse();

		MockClientHttpResponse response = new MockClientHttpResponse(HttpStatus.OK);

		Mono<OAuth2AccessTokenResponse> result = extractor.extract(response, this.context);

		assertThatCode(result::block)
				.isInstanceOf(OAuth2AuthorizationException.class)
				.hasMessageContaining("Empty OAuth 2.0 Access Token Response");
	}

	@Test
	public void oauth2AccessTokenResponseWhenValidThenCreated() {
		BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> extractor = OAuth2BodyExtractors
				.oauth2AccessTokenResponse();

		MockClientHttpResponse response = new MockClientHttpResponse(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		response.setBody("{\n"
			+ "       \"access_token\":\"2YotnFZFEjr1zCsicMWpAA\",\n"
			+ "       \"token_type\":\"Bearer\",\n"
			+ "       \"expires_in\":3600,\n"
			+ "       \"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\",\n"
			+ "       \"example_parameter\":\"example_value\"\n"
			+ "     }");

		Instant now = Instant.now();
		OAuth2AccessTokenResponse result = extractor.extract(response, this.context).block();

		assertThat(result.getAccessToken().getTokenValue()).isEqualTo("2YotnFZFEjr1zCsicMWpAA");
		assertThat(result.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(result.getAccessToken().getExpiresAt()).isBetween(now.plusSeconds(3600), now.plusSeconds(3600 + 2));
		assertThat(result.getRefreshToken().getTokenValue()).isEqualTo("tGzv3JOkF0XG5Qx2TlKWIA");
		assertThat(result.getAdditionalParameters()).containsEntry("example_parameter", "example_value");
	}


	@Test
	// gh-6087
	public void oauth2AccessTokenResponseWhenMultipleAttributeTypesThenCreated() {
		BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> extractor = OAuth2BodyExtractors
				.oauth2AccessTokenResponse();

		MockClientHttpResponse response = new MockClientHttpResponse(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		response.setBody("{\n"
				+ "       \"access_token\":\"2YotnFZFEjr1zCsicMWpAA\",\n"
				+ "       \"token_type\":\"Bearer\",\n"
				+ "       \"expires_in\":3600,\n"
				+ "       \"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\",\n"
				+ "       \"subjson\":{}, \n"
				+ "		  \"list\":[]  \n"
				+ "     }");

		Instant now = Instant.now();
		OAuth2AccessTokenResponse result = extractor.extract(response, this.context).block();

		assertThat(result.getAccessToken().getTokenValue()).isEqualTo("2YotnFZFEjr1zCsicMWpAA");
		assertThat(result.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(result.getAccessToken().getExpiresAt()).isBetween(now.plusSeconds(3600), now.plusSeconds(3600 + 2));
		assertThat(result.getRefreshToken().getTokenValue()).isEqualTo("tGzv3JOkF0XG5Qx2TlKWIA");
		assertThat(result.getAdditionalParameters().get("subjson")).isInstanceOfAny(Map.class);
		assertThat(result.getAdditionalParameters().get("list")).isInstanceOfAny(List.class);
	}
}
