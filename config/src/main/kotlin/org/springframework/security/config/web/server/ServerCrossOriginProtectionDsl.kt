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

package org.springframework.security.config.web.server

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] CSRF protection that checks where each
 * request came from, instead of requiring a token, using idiomatic Kotlin code.
 *
 * @author Scott Murphy Heiberg
 * @since 7.2
 * @property trustedOrigins origins whose requests are allowed even though they come from
 * another origin, each written as a browser sends it in the `Origin` header, such as
 * `https://partner.example`.
 */
@ServerSecurityMarker
class ServerCrossOriginProtectionDsl {
    var trustedOrigins: List<String>? = null

    internal fun get(): (ServerHttpSecurity.CsrfSpec.CrossOriginProtectionSpec) -> Unit {
        return { crossOriginProtection ->
            trustedOrigins?.also { crossOriginProtection.trustedOrigins(*it.toTypedArray()) }
        }
    }
}
