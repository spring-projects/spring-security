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

package org.springframework.security.config.annotation.web.oauth2.resourceserver

import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata

/**
 * A Kotlin DSL to configure OAuth 2.0 Protected Resource Metadata support using
 * idiomatic Kotlin code.
 *
 * @author Andrey Litvitski
 * @since 7.1
 */
@OAuth2ResourceServerSecurityMarker
class ProtectedResourceMetadataDsl {

    private var protectedResourceMetadataCustomizer: ((OAuth2ProtectedResourceMetadata.Builder) -> Unit)? = null

    /**
     * Sets the customizer providing access to the protected resource metadata builder.
     *
     * @param protectedResourceMetadataCustomizer the customizer providing access to the protected
     * resource metadata builder.
     */
    fun protectedResourceMetadataCustomizer(
        protectedResourceMetadataCustomizer: (OAuth2ProtectedResourceMetadata.Builder) -> Unit
    ) {
        this.protectedResourceMetadataCustomizer = protectedResourceMetadataCustomizer
    }

    internal fun get(): (OAuth2ResourceServerConfigurer.ProtectedResourceMetadataConfigurer) -> Unit {
        return { protectedResourceMetadata ->
            protectedResourceMetadataCustomizer?.also { customizer ->
                protectedResourceMetadata.protectedResourceMetadataCustomizer { builder ->
                    customizer(builder)
                }
            }
        }
    }

}
