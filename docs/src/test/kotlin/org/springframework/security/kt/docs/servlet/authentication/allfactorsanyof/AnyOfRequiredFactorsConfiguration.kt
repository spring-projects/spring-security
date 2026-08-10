package org.springframework.security.kt.docs.servlet.authentication.allfactorsanyof

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class AnyOfRequiredFactorsConfiguration {

	// tag::httpSecurity[]
	@Bean
	@Throws(Exception::class)
	fun springSecurity(http: HttpSecurity): SecurityFilterChain? {
		// @formatter:off
		// <1>
		val webauthn = AllRequiredFactorsAuthorizationManager.builder<Any>()
			.requireFactor { factor -> factor.webauthnAuthority() }
			.build()
		// <2>
		val passwordAndOtt = AllRequiredFactorsAuthorizationManager.builder<Any>()
			.requireFactor { factor -> factor.passwordAuthority() }
			.requireFactor { factor -> factor.ottAuthority() }
			.build()
		// <3>
		val mfa = DefaultAuthorizationManagerFactory<Any>()
		mfa.setAdditionalAuthorization(AllRequiredFactorsAuthorizationManager.anyOf(webauthn, passwordAndOtt))
		http {
			authorizeHttpRequests {
				// <4>
				authorize("/protected/**", mfa.authenticated())
				// <5>
				authorize(anyRequest, authenticated)
			}
			// <6>
			formLogin { }
			oneTimeTokenLogin { }
			webAuthn {
				rpName = "Spring Security"
				rpId = "example.com"
				allowedOrigins = setOf("https://example.com")
			}
		}
		// @formatter:on
		return http.build()
	}

	// end::httpSecurity[]

	@Suppress("DEPRECATION")
	@Bean
	fun userDetailsService(): UserDetailsService {
		return InMemoryUserDetailsManager(
			User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.authorities("app")
				.build()
		)
	}

	@Bean
	fun tokenGenerationSuccessHandler(): OneTimeTokenGenerationSuccessHandler {
		return RedirectOneTimeTokenGenerationSuccessHandler("/ott/sent")
	}

}
