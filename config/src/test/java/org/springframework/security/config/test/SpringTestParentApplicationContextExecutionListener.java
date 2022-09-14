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

package org.springframework.security.config.test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;

public class SpringTestParentApplicationContextExecutionListener implements TestExecutionListener {

	@Override
	public void beforeTestMethod(TestContext testContext) throws Exception {
		ApplicationContext parent = testContext.getApplicationContext();
		Object testInstance = testContext.getTestInstance();
		getContexts(testInstance).forEach((springTestContext) -> springTestContext
				.postProcessor((applicationContext) -> applicationContext.setParent(parent)));
	}

	private static List<SpringTestContext> getContexts(Object test) throws IllegalAccessException {
		Field[] declaredFields = test.getClass().getDeclaredFields();
		List<SpringTestContext> result = new ArrayList<>();
		for (Field field : declaredFields) {
			if (SpringTestContext.class.isAssignableFrom(field.getType())) {
				result.add((SpringTestContext) field.get(test));
			}
		}
		return result;
	}

}
