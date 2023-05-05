/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web

import org.springframework.security.authentication.AuthenticationManagerResolver
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.oauth2.resourceserver.JwtDsl
import org.springframework.security.config.annotation.web.oauth2.resourceserver.OpaqueTokenDsl
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.access.AccessDeniedHandler
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2MetadataConfigurer
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver

/**
 * A Kotlin DSL to configure [HttpSecurity] SAML 2.0 relying party metadata support using
 * idiomatic Kotlin code.
 *
 * @author Josh Cummings
 * @since 6.1
 * @property metadataUrl the name of the relying party metadata endpoint; defaults to `/saml2/metadata` and `/saml2/metadata/{registrationId}`
 * @property metadataResponseResolver the [Saml2MetadataResponseResolver] to use for resolving the
 * metadata request into metadata
 */
@SecurityMarker
class Saml2MetadataDsl {
    var metadataUrl: String? = null
    var metadataResponseResolver: Saml2MetadataResponseResolver? = null

    internal fun get(): (Saml2MetadataConfigurer<HttpSecurity>) -> Unit {
        return { saml2Metadata ->
            metadataResponseResolver?.also { saml2Metadata.metadataResponseResolver(metadataResponseResolver) }
            metadataUrl?.also { saml2Metadata.metadataUrl(metadataUrl) }
        }
    }
}
