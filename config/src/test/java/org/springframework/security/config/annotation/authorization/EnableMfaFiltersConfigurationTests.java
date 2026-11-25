/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.authorization;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link EnableMfaFiltersConfiguration}.
 */
@ExtendWith(SpringTestContextExtension.class)
public class EnableMfaFiltersConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	void registerWhenEnableMultiFactorAuthenticationThenNoBeanPostProcessorCheckerWarning() {
		Logger logger = (Logger) LoggerFactory.getLogger(
				"org.springframework.context.support.PostProcessorRegistrationDelegate$BeanPostProcessorChecker");
		ListAppender<ILoggingEvent> appender = new ListAppender<>();
		appender.start();
		logger.addAppender(appender);
		try {
			this.spring.register(MfaConfig.class).autowire();
			assertThat(appender.list).noneMatch((event) -> event.getFormattedMessage().contains("mfaBeanPostProcessor")
					|| event.getFormattedMessage().contains("EnableMfaFiltersConfiguration"));
		}
		finally {
			logger.detachAppender(appender);
			appender.stop();
		}
	}

	@EnableWebSecurity
	@Configuration
	@EnableMultiFactorAuthentication(
			authorities = { FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY })
	static class MfaConfig {

	}

}
