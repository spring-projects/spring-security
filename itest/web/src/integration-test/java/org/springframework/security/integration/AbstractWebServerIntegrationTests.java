/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.integration;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import org.junit.After;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

/**
 * Base class which allows the application to be started with a particular Spring
 * application context. Subclasses override the <tt>getContextConfigLocations</tt> method
 * to return a list of context file names which is passed to the
 * <tt>ContextLoaderListener</tt> when starting up the webapp.
 *
 * @author Luke Taylor
 */
public abstract class AbstractWebServerIntegrationTests {
	protected ConfigurableApplicationContext context;

	@After
	public void close() {
		if (context != null) {
			context.close();
		}
	}

	protected final MockMvc createMockMvc(String... configLocations) throws Exception {
		if (this.context != null) {
			throw new IllegalStateException("context is already loaded");
		}

		XmlWebApplicationContext context = new XmlWebApplicationContext();
		context.setConfigLocations(configLocations);
		context.setServletContext(new MockServletContext());
		context.refresh();
		this.context = context;

		return MockMvcBuilders
			.webAppContextSetup(context)
			.apply(springSecurity())
			.build();
	}
}
