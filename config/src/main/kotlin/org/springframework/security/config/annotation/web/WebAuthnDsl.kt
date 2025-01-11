/*
 * Copyright 2002-2025 the original author or authors.
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
import org.springframework.security.config.annotation.web.configurers.WebAuthnConfigurer

/**
 * A Kotlin DSL to configure [HttpSecurity] webauthn using idiomatic Kotlin code.
 * @property rpName the relying party name
 * @property rpId the relying party id
 * @property the allowed origins
 * @property disableDefaultRegistrationPage disable default webauthn registration page
 * @since 6.4
 * @author Rob Winch
 * @author Max Batischev
 */
@SecurityMarker
class WebAuthnDsl {
    var rpName: String? = null
    var rpId: String? = null
    var allowedOrigins: Set<String>? = null
    var disableDefaultRegistrationPage: Boolean? = false

    internal fun get(): (WebAuthnConfigurer<HttpSecurity>) -> Unit {
        return { webAuthn ->
            rpName?.also { webAuthn.rpName(rpName) }
            rpId?.also { webAuthn.rpId(rpId) }
            allowedOrigins?.also { webAuthn.allowedOrigins(allowedOrigins) }
            disableDefaultRegistrationPage?.also { webAuthn.disableDefaultRegistrationPage(disableDefaultRegistrationPage!!) }
        }
    }
}
