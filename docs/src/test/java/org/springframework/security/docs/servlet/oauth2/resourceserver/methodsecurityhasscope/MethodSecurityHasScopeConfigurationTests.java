package org.springframework.security.docs.servlet.oauth2.resourceserver.methodsecurityhasscope;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@ExtendWith(SpringTestContextExtension.class)
@ExtendWith(SpringExtension.class)
@SecurityTestExecutionListeners
public class MethodSecurityHasScopeConfigurationTests {
	public final SpringTestContext spring = new SpringTestContext(this).mockMvcAfterSpringSecurityOk();

	@Autowired
	private MessageService messages;

	@Test
	@WithMockUser(authorities = "SCOPE_message:read")
	void readMessageWhenMessageReadThenAllowed() {
		this.spring.register(MethodSecurityHasScopeConfiguration.class, MessageService.class).autowire();
		this.messages.readMessage();
	}

	@Test
	@WithMockUser
	void readMessageWhenNoScopeThenDenied() {
		this.spring.register(MethodSecurityHasScopeConfiguration.class, MessageService.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.messages::readMessage);
	}

	@Test
	@WithMockUser(authorities = { "SCOPE_message:read", "FACTOR_BEARER", "FACTOR_X509" })
	void mfaReadMessageWhenMessageReadAndFactorsThenAllowed() {
		this.spring.register(MethodSecurityHasScopeMfaConfiguration.class, MessageService.class).autowire();
		this.messages.readMessage();
	}

	@Test
	@WithMockUser(authorities = { "SCOPE_message:read" })
	void mfaReadMessageWhenMessageReadThenDenied() {
		this.spring.register(MethodSecurityHasScopeMfaConfiguration.class, MessageService.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.messages::readMessage);
	}

	@Test
	@WithMockUser
	void mfaReadMessageWhenNoScopeThenDenied() {
		this.spring.register(MethodSecurityHasScopeMfaConfiguration.class, MessageService.class).autowire();
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.messages::readMessage);
	}
}
