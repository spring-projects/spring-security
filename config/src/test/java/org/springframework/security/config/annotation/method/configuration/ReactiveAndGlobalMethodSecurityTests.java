package org.springframework.security.config.annotation.method.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

public class ReactiveAndGlobalMethodSecurityTests {

	@Test
	public void enableBoth() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(Config.class)) {
			assertThat(context.getBean(ReactiveMethodSecurityConfiguration.class)).isNotNull();
			assertThat(context.getBean(GlobalMethodSecurityConfiguration.class)).isNotNull();
		}
	}

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@EnableReactiveMethodSecurity(useAuthorizationManager = false)
	static class Config {

	}

}
