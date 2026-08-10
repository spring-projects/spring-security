/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kt.docs.servlet.oauth2.resourceserver.opaquetokentimeoutsrestclient

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.introspection.RestClientOpaqueTokenIntrospector
import org.springframework.web.client.RestClient
import org.assertj.core.api.Assertions.assertThat
import java.time.Duration
import java.time.Instant
import java.util.Base64

/**
 * Tests for [RestClientOpaqueTokenIntrospectorConfiguration] sample snippets.
 */
class RestClientOpaqueTokenIntrospectorConfigurationTests {

	companion object {
		private const val CLIENT_ID = "client"
		private const val CLIENT_SECRET = "secret"
		private const val ACTIVE_RESPONSE = """
			{
			  "active": true,
			  "sub": "Z5O3upPC88QrAjx00dis",
			  "scope": "read write",
			  "exp": 1419356238,
			  "iat": 1419350238
			}
			"""
	}

	@Test
	fun introspectorWhenBuilderThenIntrospectsSuccessfully() {
		MockWebServer().use { server ->
			server.dispatcher = requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE)
			server.start()
			val introspectionUri = server.url("/introspect").toString()
			val introspector: OpaqueTokenIntrospector = RestClientOpaqueTokenIntrospector
				.withIntrospectionUri(introspectionUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build()
			val principal: OAuth2AuthenticatedPrincipal = introspector.introspect("token")
			assertThat(principal.attributes).isNotNull
			assertThat(principal.attributes).containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
			assertThat(principal.attributes).containsEntry(OAuth2TokenIntrospectionClaimNames.SUB, "Z5O3upPC88QrAjx00dis")
			assertThat(principal.attributes).containsEntry(OAuth2TokenIntrospectionClaimNames.EXP, Instant.ofEpochSecond(1419356238))
			assertThat(principal.getAttribute<Any>(OAuth2TokenIntrospectionClaimNames.SCOPE))
				.isEqualTo(listOf("read", "write"))
		}
	}

	@Test
	fun introspectorWithTimeoutsWhenCustomRestClientThenIntrospectsSuccessfully() {
		MockWebServer().use { server ->
			server.dispatcher = requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE)
			server.start()
			val introspectionUri = server.url("/introspect").toString()
			val requestFactory = SimpleClientHttpRequestFactory()
			requestFactory.setConnectTimeout(Duration.ofSeconds(60))
			requestFactory.setReadTimeout(Duration.ofSeconds(60))
			val restClient = RestClient.builder()
				.requestFactory(requestFactory)
				.defaultHeaders { headers -> headers.setBasicAuth(CLIENT_ID, CLIENT_SECRET) }
				.build()
			val introspector = RestClientOpaqueTokenIntrospector(introspectionUri, restClient)
			val principal: OAuth2AuthenticatedPrincipal = introspector.introspect("token")
			assertThat(principal.attributes).isNotNull
			assertThat(principal.attributes).containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
			assertThat(principal.attributes).containsEntry(OAuth2TokenIntrospectionClaimNames.SUB, "Z5O3upPC88QrAjx00dis")
		}
	}

	private fun requiresAuth(username: String, password: String, response: String): Dispatcher {
		return object : Dispatcher() {
			override fun dispatch(request: RecordedRequest): MockResponse {
				val authorization = request.getHeader(HttpHeaders.AUTHORIZATION)
				return if (authorization != null && isAuthorized(authorization, username, password)) {
					MockResponse()
						.setBody(response)
						.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				} else {
					MockResponse().setResponseCode(401)
				}
			}
		}
	}

	private fun isAuthorized(authorization: String, username: String, password: String): Boolean {
		val decoded = String(Base64.getDecoder().decode(authorization.substring(6)))
		val values = decoded.split(":", limit = 2)
		return values.size == 2 && username == values[0] && password == values[1]
	}
}
