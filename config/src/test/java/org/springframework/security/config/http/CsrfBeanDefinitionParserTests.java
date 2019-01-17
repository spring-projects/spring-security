/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.http;

import org.junit.Test;

import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author Ankur Pathak
 */
public class CsrfBeanDefinitionParserTests {
	private static final String CONFIG_LOCATION_PREFIX =
			"classpath:org/springframework/security/config/http/CsrfBeanDefinitionParserTests";

	@Test
	public void registerDataValueProcessorOnlyIfNotRegistered() throws Exception {
		try (ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext()) {
			context.setAllowBeanDefinitionOverriding(false);
			context.setConfigLocation(this.xml("RegisterDataValueProcessorOnyIfNotRegistered"));
			context.refresh();
		}
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
