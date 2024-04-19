package org.springframework.security.config.annotation.web.saml2

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LogoutConfigurer
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver

/**
 * A Kotlin DSL to configure SAML 2.0 Logout Response components using idiomatic Kotlin code.
 *
 * @author Josh Cummings
 * @since 6.3
 * @property logoutUrl The URL by which the asserting party can send a SAML 2.0 Logout Response.
 * The Asserting Party should use whatever HTTP method specified in {@link RelyingPartyRegistration#getSingleLogoutServiceBindings()}.
 * @property logoutResponseValidator the [Saml2LogoutResponseValidator] to use for validating incoming {@code LogoutResponse}s.
 * @property logoutResponseResolver the [Saml2LogoutResponseResolver] to use for generating outgoing {@code LogoutResponse}s.
 */
@Saml2SecurityMarker
class LogoutResponseDsl {
    var logoutUrl = "/logout/saml2/slo"
    var logoutResponseValidator: Saml2LogoutResponseValidator? = null
    var logoutResponseResolver: Saml2LogoutResponseResolver? = null

    internal fun get(): (Saml2LogoutConfigurer<HttpSecurity>.LogoutResponseConfigurer) -> Unit {
        return { logoutResponse ->
            logoutUrl.also { logoutResponse.logoutUrl(logoutUrl) }
            logoutResponseValidator?.also { logoutResponse.logoutResponseValidator(logoutResponseValidator) }
            logoutResponseResolver?.also { logoutResponse.logoutResponseResolver(logoutResponseResolver) }
        }
    }
}
