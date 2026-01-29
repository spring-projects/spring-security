package org.springframework.security.kt.docs.features.authentication.authenticationcompromisedpasswordcheck

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.password.CompromisedPasswordChecker
import org.springframework.security.authentication.password.CompromisedPasswordException
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker


open class CompromisedPasswordCheckerUsage {
    // tag::configuration[]
    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
            formLogin {
                authenticationFailureHandler = CompromisedPasswordAuthenticationFailureHandler()
            }
        }
        return http.build()
    }

    @Bean
    open fun compromisedPasswordChecker(): CompromisedPasswordChecker {
        return HaveIBeenPwnedRestApiPasswordChecker()
    }

    class CompromisedPasswordAuthenticationFailureHandler : AuthenticationFailureHandler {
        private val defaultFailureHandler = SimpleUrlAuthenticationFailureHandler("/login?error")
        private val redirectStrategy = DefaultRedirectStrategy()

        override fun onAuthenticationFailure(
            request: HttpServletRequest,
            response: HttpServletResponse,
            exception: AuthenticationException
        ) {
            if (exception is CompromisedPasswordException) {
                redirectStrategy.sendRedirect(request, response, "/reset-password")
                return
            }
            defaultFailureHandler.onAuthenticationFailure(request, response, exception)
        }
    }
    // end::configuration[]
}
