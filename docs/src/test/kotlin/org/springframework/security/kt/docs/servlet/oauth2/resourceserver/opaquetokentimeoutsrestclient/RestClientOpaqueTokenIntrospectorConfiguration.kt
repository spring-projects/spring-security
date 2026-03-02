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

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.introspection.RestClientOpaqueTokenIntrospector
import org.springframework.web.client.RestClient
import java.time.Duration

@Configuration
open class RestClientOpaqueTokenIntrospectorConfiguration {

	// tag::restclient-simple[]
	@Bean
	open fun introspector(introspectionUri: String, clientId: String, clientSecret: String): OpaqueTokenIntrospector {
		return RestClientOpaqueTokenIntrospector.withIntrospectionUri(introspectionUri)
			.clientId(clientId)
			.clientSecret(clientSecret)
			.build()
	}
	// end::restclient-simple[]

	// tag::restclient-timeouts[]
	@Bean
	open fun introspectorWithTimeouts(
		introspectionUri: String,
		clientId: String,
		clientSecret: String
	): OpaqueTokenIntrospector {
		val requestFactory = SimpleClientHttpRequestFactory()
		requestFactory.setConnectTimeout(Duration.ofSeconds(60))
		requestFactory.setReadTimeout(Duration.ofSeconds(60))
		val restClient = RestClient.builder()
			.requestFactory(requestFactory)
			.defaultHeaders { headers -> headers.setBasicAuth(clientId, clientSecret) }
			.build()
		return RestClientOpaqueTokenIntrospector(introspectionUri, restClient)
	}
	// end::restclient-timeouts[]
}
