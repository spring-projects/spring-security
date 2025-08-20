package org.springframework.security.kt.docs.servlet.configuration.toplevelcustomizerbean

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

@ExtendWith(SpringTestContextExtension::class)
class TopLevelCustomizerBeanTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `top level dsl bean`() {
        this.spring.register(TopLevelCustomizerBeanConfiguration::class.java).autowire()

        this.mockMvc.get("/")
            .andExpect {
                header {
                    string("Content-Security-Policy", "object-src 'none'")
                }
            }
    }

}
