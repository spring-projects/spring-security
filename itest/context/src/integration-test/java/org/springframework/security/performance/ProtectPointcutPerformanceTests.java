/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.performance;

import static org.assertj.core.api.Assertions.fail;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.StopWatch;

/**
 * @author Luke Taylor
 */
@ContextConfiguration(locations = { "/protect-pointcut-performance-app-context.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
public class ProtectPointcutPerformanceTests implements ApplicationContextAware {

	ApplicationContext ctx;

	@Before
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	// Method for use with profiler
	@Test
	public void usingPrototypeDoesNotParsePointcutOnEachCall() {
		StopWatch sw = new StopWatch();
		sw.start();
		for (int i = 0; i < 1000; i++) {
			try {
				SessionRegistry reg = (SessionRegistry) ctx.getBean(
						"sessionRegistryPrototype");
				reg.getAllPrincipals();
				fail("Expected AuthenticationCredentialsNotFoundException");
			}
			catch (AuthenticationCredentialsNotFoundException expected) {
			}
		}
		sw.stop();
		// assertThat(sw.getTotalTimeMillis() < 1000).isTrue();

	}

	public void setApplicationContext(ApplicationContext applicationContext)
			throws BeansException {
		ctx = applicationContext;
	}
}
