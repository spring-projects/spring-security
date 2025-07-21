/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests to verify {@code EnableWebSecurity(debug)} functionality
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceDebugTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenDebugSetToTrueThenLogsDebugInformation() throws Exception {
		Appender<ILoggingEvent> appender = mockAppenderFor("Spring Security Debugger");
		this.spring.register(DebugWebSecurity.class).autowire();
		this.mvc.perform(get("/"));
		verify(appender, atLeastOnce()).doAppend(any(ILoggingEvent.class));
	}

	@Test
	public void requestWhenDebugSetToFalseThenDoesNotLogDebugInformation() throws Exception {
		Appender<ILoggingEvent> appender = mockAppenderFor("Spring Security Debugger");
		this.spring.register(NoDebugWebSecurity.class).autowire();
		this.mvc.perform(get("/"));
		assertThat(filterChainClass()).isNotEqualTo(DebugFilter.class);
		verify(appender, never()).doAppend(any(ILoggingEvent.class));
	}

	private Appender<ILoggingEvent> mockAppenderFor(String name) {
		Appender<ILoggingEvent> appender = mock(Appender.class);
		Logger logger = (Logger) LoggerFactory.getLogger(name);
		logger.setLevel(Level.DEBUG);
		logger.addAppender(appender);
		return appender;
	}

	private Class<?> filterChainClass() {
		return this.spring.getContext().getBean("springSecurityFilterChain").getClass();
	}

	@Configuration
	@EnableWebSecurity(debug = true)
	static class DebugWebSecurity {

	}

	@Configuration
	@EnableWebSecurity
	static class NoDebugWebSecurity {

	}

}
