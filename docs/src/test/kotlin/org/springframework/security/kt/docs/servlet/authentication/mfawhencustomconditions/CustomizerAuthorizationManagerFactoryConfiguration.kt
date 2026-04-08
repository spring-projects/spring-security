package org.springframework.security.kt.docs.servlet.authentication.mfawhencustomconditions

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authorization.AuthorizationManagerFactories
import org.springframework.security.config.Customizer

@Configuration(proxyBeanMethods = false)
internal class CustomizerAuthorizationManagerFactoryConfiguration {

    // tag::customizer[]
    @Bean
    fun additionalRequiredFactorsCustomizer(): Customizer<AuthorizationManagerFactories.AdditionalRequiredFactorsBuilder<Any>> {
        return Customizer { builder -> builder.`when` { auth -> "admin" == auth.name } }
    }
    // end::customizer[]

}
