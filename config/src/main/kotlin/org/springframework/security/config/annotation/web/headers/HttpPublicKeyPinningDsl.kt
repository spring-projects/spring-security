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

package org.springframework.security.config.annotation.web.headers

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer

/**
 * A Kotlin DSL to configure the [HttpSecurity] HTTP Public Key Pinning header using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property pins the value for the pin- directive of the Public-Key-Pins header.
 * @property maxAgeInSeconds the value (in seconds) for the max-age directive of the
 * Public-Key-Pins header.
 * @property includeSubDomains if true, the pinning policy applies to this pinned host
 * as well as any subdomains of the host's domain name.
 * @property reportOnly if true, the browser should not terminate the connection with
 * the server.
 * @property reportUri the URI to which the browser should report pin validation failures.
 * @deprecated see <a href="https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning">Certificate and Public Key Pinning</a> for more context
 */
@HeadersSecurityMarker
@Deprecated(message = "as of 5.8 with no replacement")
class HttpPublicKeyPinningDsl {
    var pins: Map<String, String>? = null
    var maxAgeInSeconds: Long? = null
    var includeSubDomains: Boolean? = null
    var reportOnly: Boolean? = null
    var reportUri: String? = null

    private var disabled = false

    /**
     * Disable the HTTP Public Key Pinning header.
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (HeadersConfigurer<HttpSecurity>.HpkpConfig) -> Unit {
        return { hpkp ->
            pins?.also {
                hpkp.withPins(pins)
            }
            maxAgeInSeconds?.also {
                hpkp.maxAgeInSeconds(maxAgeInSeconds!!)
            }
            includeSubDomains?.also {
                hpkp.includeSubDomains(includeSubDomains!!)
            }
            reportOnly?.also {
                hpkp.reportOnly(reportOnly!!)
            }
            reportUri?.also {
                hpkp.reportUri(reportUri)
            }
            if (disabled) {
                hpkp.disable()
            }
        }
    }
}
