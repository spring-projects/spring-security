package org.springframework.security.kt.docs.servlet.oauth2.resourceserver.methodsecurityhasscope

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.oauth2.core.authorization.DefaultOAuth2AuthorizationManagerFactory
import org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagerFactory

@Configuration
@EnableMethodSecurity
open class MethodSecurityHasScopeConfiguration {
    // tag::declare-factory[]
    @Bean
    open fun oauth2(): OAuth2AuthorizationManagerFactory<Any> {
        return DefaultOAuth2AuthorizationManagerFactory()
    }
    // end::declare-factory[]
}
