/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.web.headers

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter

/**
 * A Kotlin DSL to configure the [HttpSecurity] Cross-Origin-Resource-Policy header using
 * idiomatic Kotlin code.
 *
 * @author Marcus Da Coregio
 * @since 5.7
 * @property policy the policy to be used in the response header.
 */
@HeadersSecurityMarker
class CrossOriginResourcePolicyDsl {

    var policy: CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy? = null

    internal fun get(): (HeadersConfigurer<HttpSecurity>.CrossOriginResourcePolicyConfig) -> Unit {
        return { crossOriginResourcePolicy ->
            policy?.also {
                crossOriginResourcePolicy.policy(policy)
            }
        }
    }
}
