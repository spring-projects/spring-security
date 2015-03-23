/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.context.support;

import static org.mockito.Mockito.when;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.context.TestContext;
import org.springframework.util.ReflectionUtils;

@RunWith(MockitoJUnitRunner.class)
public class WithSecurityContextTestExcecutionListenerTests {
	private ConfigurableApplicationContext context;

	@Mock
	private TestContext testContext;

	private WithSecurityContextTestExecutionListener listener;

	@Before
	public void setup() {
		listener = new WithSecurityContextTestExecutionListener();
		context = new AnnotationConfigApplicationContext(Config.class);
	}

	@After
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
		if (context != null) {
			context.close();
		}
	}

	@Test
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void beforeTestMethodNullSecurityContextNoError() throws Exception {
		Class testClass = FakeTest.class;
		when(testContext.getApplicationContext()).thenReturn(context);
		when(testContext.getTestClass()).thenReturn(testClass);
		when(testContext.getTestMethod()).thenReturn(
				ReflectionUtils.findMethod(testClass, "testNoAnnotation"));

		listener.beforeTestMethod(testContext);
	}

	static class FakeTest {
		public void testNoAnnotation() {
		}
	}

	@Configuration
	static class Config {
	}
}
