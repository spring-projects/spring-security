package org.springframework.security.kt.docs.servlet.configuration.httpsecuritycustomizerbean

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

@ExtendWith(SpringTestContextExtension::class)
class HttpSecurityCustomizerBeanTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `httpsecurity customizer config`() {
        this.spring.register(HttpSecurityCustomizerBeanConfiguration::class.java).autowire()

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
