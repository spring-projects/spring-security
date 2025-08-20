package org.springframework.security.kt.docs.servlet.configuration.httpsecuritydslbean

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get


@ExtendWith(SpringTestContextExtension::class)
class HttpSecurityDslBeanTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `HttpSecurityDslBean`() {
        this.spring.register(HttpSecurityDslBeanConfiguration::class.java).autowire()

        this.mockMvc.get("/")
            .andExpect {
                redirectedUrl("https://localhost/")
            }

        this.mockMvc.get("https://localhost/")
            .andExpect {
                header {
                    string("Content-Security-Policy", "object-src 'none'")
                }
            }
    }
}
