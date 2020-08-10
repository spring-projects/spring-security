/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.access.annotation.sec2150;

import org.springframework.aop.framework.ProxyFactory;
import org.springframework.security.access.intercept.method.MockMethodInvocation;

public class MethodInvocationFactory {

	/**
	 * In order to reproduce the bug for SEC-2150, we must have a proxy object that
	 * implements TargetSourceAware and implements our annotated interface.
	 * @return
	 * @throws NoSuchMethodException
	 */
	public static MockMethodInvocation createSec2150MethodInvocation() throws NoSuchMethodException {
		ProxyFactory factory = new ProxyFactory(new Class[] { PersonRepository.class });
		factory.setTargetClass(CrudRepository.class);
		PersonRepository repository = (PersonRepository) factory.getProxy();
		return new MockMethodInvocation(repository, PersonRepository.class, "findAll");
	}

}
