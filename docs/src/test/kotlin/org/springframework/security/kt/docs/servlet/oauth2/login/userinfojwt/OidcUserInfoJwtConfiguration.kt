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

package org.springframework.security.kt.docs.servlet.oauth2.login.userinfojwt

import com.nimbusds.jose.jwk.JWK
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserInfoJwtDecoderFactory
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.web.SecurityFilterChain

@Configuration
open class OidcUserInfoJwtConfiguration {

	// tag::filter-chain[]
	@Bean
	open fun filterChain(
		http: HttpSecurity,
		oidcUserService: OAuth2UserService<OidcUserRequest, OidcUser>
	): SecurityFilterChain {
		http {
			oauth2Login {
				userInfoEndpoint {
					this.oidcUserService = oidcUserService
				}
			}
		}
		return http.build()
	}
	// end::filter-chain[]

	// tag::user-service[]
	@Bean
	open fun oidcUserService(decryptionKey: JWK): OAuth2UserService<OidcUserRequest, OidcUser> {
		val decoderFactory = OidcUserInfoJwtDecoderFactory()
		// the client registered userinfo_signed_response_alg=ES256 (the default is RS256)
		decoderFactory.setJwsAlgorithmResolver { SignatureAlgorithm.ES256 }
		// only needed if the Provider also encrypts the response
		decoderFactory.setJweDecryptionKeyResolver { decryptionKey }

		val delegate = DefaultOAuth2UserService()
		delegate.setJwtResponseConverter { userRequest ->
			Converter { jwt ->
				decoderFactory.createDecoder(userRequest.clientRegistration).decode(jwt).claims
			}
		}

		val oidcUserService = OidcUserService()
		oidcUserService.setOauth2UserService(delegate)
		return oidcUserService
	}
	// end::user-service[]

}
