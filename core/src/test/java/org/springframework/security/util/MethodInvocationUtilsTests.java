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

package org.springframework.security.util;

import java.io.Serializable;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;

import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.security.access.annotation.BusinessServiceImpl;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class MethodInvocationUtilsTests {

	@Test
	public void createFromClassReturnsMethodWithNoArgInfoForMethodWithNoArgs() {
		MethodInvocation mi = MethodInvocationUtils.createFromClass(String.class, "length");
		assertThat(mi).isNotNull();
	}

	@Test
	public void createFromClassReturnsMethodIfArgInfoOmittedAndMethodNameIsUnique() {
		MethodInvocation mi = MethodInvocationUtils.createFromClass(BusinessServiceImpl.class,
				"methodReturningAnArray");
		assertThat(mi).isNotNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void exceptionIsRaisedIfArgInfoOmittedAndMethodNameIsNotUnique() {
		MethodInvocationUtils.createFromClass(BusinessServiceImpl.class, "methodReturningAList");
	}

	@Test
	public void createFromClassReturnsMethodIfGivenArgInfoForMethodWithArgs() {
		MethodInvocation mi = MethodInvocationUtils.createFromClass(null, String.class, "compareTo",
				new Class<?>[] { String.class }, new Object[] { "" });
		assertThat(mi).isNotNull();
	}

	@Test
	public void createFromObjectLocatesExistingMethods() {
		AdvisedTarget t = new AdvisedTarget();
		// Just lie about interfaces
		t.setInterfaces(new Class[] { Serializable.class, MethodInvocation.class, Blah.class });

		MethodInvocation mi = MethodInvocationUtils.create(t, "blah");
		assertThat(mi).isNotNull();

		t.setProxyTargetClass(true);
		mi = MethodInvocationUtils.create(t, "blah");
		assertThat(mi).isNotNull();

		assertThat(MethodInvocationUtils.create(t, "blah", "non-existent arg")).isNull();
	}

	interface Blah {

		void blah();

	}

	class AdvisedTarget extends AdvisedSupport implements Blah {

		@Override
		public void blah() {
		}

	}

}
