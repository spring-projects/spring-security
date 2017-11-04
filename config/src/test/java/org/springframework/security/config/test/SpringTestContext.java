/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.config.test;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.io.Closeable;
import java.io.IOException;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SpringTestContext implements Closeable {
	private Object test;

	private ConfigurableApplicationContext context;

	public void setTest(Object test) {
		this.test = test;
	}

	@Override
	public void close() throws IOException {
		this.context.close();
	}

	public SpringTestContext register(Class<?>... classes) {
		AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
		applicationContext.setServletContext(new MockServletContext());
		applicationContext.setServletConfig(new MockServletConfig());
		applicationContext.register(classes);
		this.context = applicationContext;
		return this;
	}

	public ConfigurableApplicationContext getContext() {
		return this.context;
	}

	public void autowire() {
		this.context.refresh();
		this.context.getBeanFactory().autowireBean(this.test);
	}
}
