package org.springframework.security.kt.docs.servlet.authentication.obtainingmoreauthorization

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.TestClientRegistrations
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class ScopeConfiguration {
    // tag::httpSecurity[]
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        http {
            authorizeHttpRequests {
                authorize("/profile/**", hasAuthority("SCOPE_profile:read"))
                authorize(anyRequest, authenticated)
            }
            x509 { }
            oauth2Login { }
        }
        // @formatter:on
        return http.build()
    }
    // end::httpSecurity[]

    @Bean
    fun clients(): ClientRegistrationRepository {
        return InMemoryClientRegistrationRepository(TestClientRegistrations.clientRegistration().build())
    }
}
