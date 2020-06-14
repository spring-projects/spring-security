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

package org.springframework.security.config.web.server

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono
import java.security.interfaces.RSAPublicKey

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] JWT Resource Server support using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property authenticationManager the [ReactiveAuthenticationManager] used to determine if the provided
 * [Authentication] can be authenticated.
 * @property jwtAuthenticationConverter the [Converter] to use for converting a [Jwt] into an
 * [AbstractAuthenticationToken].
 * @property jwtDecoder the [ReactiveJwtDecoder] to use.
 * @property publicKey configures a [ReactiveJwtDecoder] that leverages the provided [RSAPublicKey]
 * @property jwkSetUri configures a [ReactiveJwtDecoder] using a
 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a> URL
 */
@ServerSecurityMarker
class ServerJwtDsl {
    private var _jwtDecoder: ReactiveJwtDecoder? = null
    private var _publicKey: RSAPublicKey? = null
    private var _jwkSetUri: String? = null
    private var _webClient: WebClient? = null

    var authenticationManager: ReactiveAuthenticationManager? = null
    var jwtAuthenticationConverter: Converter<Jwt, out Mono<out AbstractAuthenticationToken>>? = null

    var jwtDecoder: ReactiveJwtDecoder?
        get() = _jwtDecoder
        set(value) {
            _jwtDecoder = value
            _publicKey = null
            _jwkSetUri = null
        }
    var publicKey: RSAPublicKey?
        get() = _publicKey
        set(value) {
            _publicKey = value
            _jwtDecoder = null
            _jwkSetUri = null
        }
    var jwkSetUri: String?
        get() = _jwkSetUri
        set(value) {
            _jwkSetUri = value
            _jwtDecoder = null
            _publicKey = null
        }
    var webClient: WebClient?
        get() = _webClient
        set(value) {
            _webClient = value
        }

    internal fun get(): (ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec) -> Unit {
        return { jwt ->
            authenticationManager?.also { jwt.authenticationManager(authenticationManager) }
            jwtAuthenticationConverter?.also { jwt.jwtAuthenticationConverter(jwtAuthenticationConverter) }
            publicKey?.also { jwt.publicKey(publicKey) }
            webClient?.also { jwt.webClient(webClient) }
            jwkSetUri?.also { jwt.jwkSetUri(jwkSetUri) }
            jwtDecoder?.also { jwt.jwtDecoder(jwtDecoder) }
        }
    }
}
