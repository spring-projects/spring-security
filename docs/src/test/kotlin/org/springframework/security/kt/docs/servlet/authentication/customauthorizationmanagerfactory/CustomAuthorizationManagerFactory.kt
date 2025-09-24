package org.springframework.security.kt.docs.servlet.authentication.customauthorizationmanagerfactory

import org.jspecify.annotations.NullMarked
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.expression.SecurityExpressionRoot
import org.springframework.security.authorization.*
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler
import org.springframework.stereotype.Component
import java.util.function.Supplier

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class CustomAuthorizationManagerFactory {

    // tag::httpSecurity[]
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        http {
            authorizeHttpRequests {
                authorize("/admin/**", hasRole("ADMIN"))
                authorize(anyRequest, authenticated)
            }
            formLogin { }
            oneTimeTokenLogin { }
        }
        // @formatter:on
        return http.build()
    }
    // end::httpSecurity[]

    // tag::authorizationManager[]
    @Component
    internal open class OptInToMfaAuthorizationManager : AuthorizationManager<Object> {
        override fun authorize(
            authentication: Supplier<out Authentication?>, context: Object): AuthorizationResult {
            val principal = authentication.get().getPrincipal() as MyPrincipal?
            if (principal!!.optedIn) {
                val root = object : SecurityExpressionRoot<Object>(authentication, context) { }
                return AuthorityAuthorizationDecision(
                    root.hasAuthority("FACTOR_OTT"),
                    AuthorityUtils.createAuthorityList("FACTOR_OTT")
                )
            }
            return AuthorizationDecision(true)
        }
    }
    // end::authorizationManager[]

    // tag::authorizationManagerFactory[]
    @Bean
    fun authorizationManagerFactory(optIn: OptInToMfaAuthorizationManager?): AuthorizationManagerFactory<Object> {
        val defaults = DefaultAuthorizationManagerFactory<Object>()
        defaults.setAdditionalAuthorization(optIn)
        return defaults
    }
    // end::authorizationManagerFactory[]

    @NullMarked
    class MyPrincipal(val user: String, val optedIn: Boolean) : UserDetails {
        override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
            return AuthorityUtils.createAuthorityList("app")
        }

        override fun getPassword(): String? {
            return null
        }

        override fun getUsername(): String {
            return this.user
        }

    }

    @Bean
    fun users(): UserDetailsService {
        return UserDetailsService { username: String? -> MyPrincipal(username!!, username == "optedin") }
    }

    @Bean
    fun tokenGenerationSuccessHandler(): OneTimeTokenGenerationSuccessHandler {
        return RedirectOneTimeTokenGenerationSuccessHandler("/ott/sent")
    }
}
