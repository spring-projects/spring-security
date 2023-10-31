/*
 * Copyright 2002-2017 the original author or authors.
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

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import org.springframework.security.test.context.TestSecurityContextHolder;

public class SpringTestContextExtension implements BeforeEachCallback, AfterEachCallback {

	@Override
	public void afterEach(ExtensionContext context) throws Exception {
		TestSecurityContextHolder.clearContext();
		getContexts(context.getRequiredTestInstance()).forEach((springTestContext) -> springTestContext.close());
	}

	@Override
	public void beforeEach(ExtensionContext context) throws Exception {
		Object testInstance = context.getRequiredTestInstance();
		getContexts(testInstance).forEach((springTestContext) -> springTestContext.setTest(testInstance));
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
