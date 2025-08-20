package org.springframework.security.kt.docs.reactive.configuration.serverhttpsecuritycustomizerbean

import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.test.web.reactive.server.WebTestClient
import java.util.function.Consumer

@ExtendWith(SpringTestContextExtension::class)
class ServerHttpSecurityCustomizerBeanTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var webTest: WebTestClient

    @Test
    fun `serverhttpsecurity customizer config`() {
        this.spring.register(ServerHttpSecurityCustomizerBeanConfiguration::class.java).autowire()
        // @formatter:off
        this.webTest
            .get()
            .uri("http://localhost/")
            .exchange()
            .expectHeader().location("https://localhost/")
            .expectHeader()
            .value("Content-Security-Policy", Consumer { csp ->
                assertThat(csp).isEqualTo("object-src 'none'")
            })
            // @formatter:on
    }

}
