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

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer
import org.springframework.security.web.context.SecurityContextRepository


/**
 * A Kotlin DSL to configure [HttpSecurity] security context using idiomatic Kotlin code.
 *
 * @property securityContextRepository the [SecurityContextRepository] used for persisting [org.springframework.security.core.context.SecurityContext] between requests
 * @author Norbert Nowak
 * @since 5.7
 */
@SecurityMarker
class SecurityContextDsl {

    var securityContextRepository: SecurityContextRepository? = null
    var requireExplicitSave: Boolean? = null

    internal fun get(): (SecurityContextConfigurer<HttpSecurity>) -> Unit {
        return { securityContext ->
            securityContextRepository?.also { securityContext.securityContextRepository(it) }
            requireExplicitSave?.also { securityContext.requireExplicitSave(it) }
        }
    }
}
