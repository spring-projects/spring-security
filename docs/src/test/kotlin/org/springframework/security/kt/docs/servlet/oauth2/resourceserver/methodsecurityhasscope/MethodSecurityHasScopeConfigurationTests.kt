package org.springframework.security.kt.docs.servlet.oauth2.resourceserver.methodsecurityhasscope

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.junit.jupiter.SpringExtension

@ExtendWith(SpringTestContextExtension::class)
@ExtendWith(SpringExtension::class)
@SecurityTestExecutionListeners
class MethodSecurityHasScopeConfigurationTests {
    @JvmField
    val spring: SpringTestContext = SpringTestContext(this).mockMvcAfterSpringSecurityOk()

    @Autowired
    var messages: MessageService? = null

    @Test
    @WithMockUser(authorities = ["SCOPE_message:read"])
    fun readMessageWhenMessageReadThenAllowed() {
        this.spring.register(MethodSecurityHasScopeConfiguration::class.java, MessageService::class.java).autowire()
        this.messages!!.readMessage()
    }

    @Test
    @WithMockUser
    fun readMessageWhenNoScopeThenDenied() {
        this.spring.register(MethodSecurityHasScopeConfiguration::class.java, MessageService::class.java).autowire()
        Assertions.assertThatExceptionOfType<AccessDeniedException?>(AccessDeniedException::class.java)
            .isThrownBy({ this.messages!!.readMessage() })
    }

    @Test
    @WithMockUser(authorities = ["SCOPE_message:read", "FACTOR_BEARER", "FACTOR_X509"])
    fun mfaReadMessageWhenMessageReadAndFactorsThenAllowed() {
        this.spring.register(MethodSecurityHasScopeMfaConfiguration::class.java, MessageService::class.java).autowire()
        this.messages!!.readMessage()
    }

    @Test
    @WithMockUser(authorities = ["SCOPE_message:read"])
    fun mfaReadMessageWhenMessageReadThenDenied() {
        this.spring.register(MethodSecurityHasScopeMfaConfiguration::class.java, MessageService::class.java).autowire()
        Assertions.assertThatExceptionOfType<AccessDeniedException?>(AccessDeniedException::class.java)
            .isThrownBy({ this.messages!!.readMessage() })
    }

    @Test
    @WithMockUser
    fun mfaReadMessageWhenNoScopeThenDenied() {
        this.spring.register(MethodSecurityHasScopeMfaConfiguration::class.java, MessageService::class.java).autowire()
        Assertions.assertThatExceptionOfType<AccessDeniedException?>(AccessDeniedException::class.java)
            .isThrownBy({ this.messages!!.readMessage() })
    }
}
