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

package org.springframework.security.config.annotation.web.configuration.sec2377;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.config.annotation.web.configuration.sec2377.a.Sec2377AConfig;
import org.springframework.security.config.annotation.web.configuration.sec2377.b.Sec2377BConfig;
import org.springframework.security.config.test.SpringTestRule;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
public class Sec2377Tests {

	@Rule
	public final SpringTestRule parent = new SpringTestRule();

	@Rule
	public final SpringTestRule child = new SpringTestRule();

	@Test
	public void refreshContextWhenParentAndChildRegisteredThenNoException() {
		this.parent.register(Sec2377AConfig.class).autowire();

		ConfigurableApplicationContext context = this.child.register(Sec2377BConfig.class).getContext();
		context.setParent(this.parent.getContext());

		this.child.autowire();
	}

}
