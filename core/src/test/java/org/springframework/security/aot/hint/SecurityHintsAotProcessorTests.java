/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.aot.hint;

import org.junit.jupiter.api.Test;

import org.springframework.aot.generate.GenerationContext;
import org.springframework.aot.test.generate.TestGenerationContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.context.aot.ApplicationContextAotGenerator;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link SecurityHintsAotProcessor}
 */
public class SecurityHintsAotProcessorTests {

	@Test
	void applyToWhenSecurityHintsRegistrarThenInvokes() {
		GenerationContext generationContext = new TestGenerationContext();
		AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
		context.register(AppConfig.class);
		ApplicationContextAotGenerator generator = new ApplicationContextAotGenerator();
		generator.processAheadOfTime(context, generationContext);
		verify(context.getBean(SecurityHintsRegistrar.class)).registerHints(any(), any());
	}

	@Configuration
	static class AppConfig {

		@Bean
		@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
		static SecurityHintsRegistrar hints() {
			return mock(SecurityHintsRegistrar.class);
		}

	}

}
