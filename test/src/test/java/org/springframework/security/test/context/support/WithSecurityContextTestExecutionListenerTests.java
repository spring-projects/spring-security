/*
 * Copyright 2002-2015 the original author or authors.
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

import static org.assertj.core.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.test.context.TestExecutionListener;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;

/**
 * @author Rob Winch
 *
 */
public class WithSecurityContextTestExecutionListenerTests {
	WithSecurityContextTestExecutionListener listener;

	@Before
	public void setup() {
		listener = new WithSecurityContextTestExecutionListener();
	}

	// SEC-2709
	@Test
	public void orderOverridden() {
		DependencyInjectionTestExecutionListener otherListener = new DependencyInjectionTestExecutionListener();

		List<TestExecutionListener> listeners = new ArrayList<TestExecutionListener>();
		listeners.add(otherListener);
		listeners.add(listener);

		AnnotationAwareOrderComparator.sort(listeners);

		assertThat(listeners).containsSequence(listener, otherListener);
	}
}
