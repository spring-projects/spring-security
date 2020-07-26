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
package org.springframework.security.config.annotation;

import org.junit.Before;
import org.junit.Test;

import org.springframework.core.Ordered;

import static org.assertj.core.api.Assertions.assertThat;

public class SecurityConfigurerAdapterTests {

	ConcereteSecurityConfigurerAdapter adapter;

	@Before
	public void setup() {
		this.adapter = new ConcereteSecurityConfigurerAdapter();
	}

	@Test
	public void postProcessObjectPostProcessorsAreSorted() {
		this.adapter.addObjectPostProcessor(new OrderedObjectPostProcessor(Ordered.LOWEST_PRECEDENCE));
		this.adapter.addObjectPostProcessor(new OrderedObjectPostProcessor(Ordered.HIGHEST_PRECEDENCE));

		assertThat(this.adapter.postProcess("hi"))
				.isEqualTo("hi " + Ordered.HIGHEST_PRECEDENCE + " " + Ordered.LOWEST_PRECEDENCE);
	}

	static class OrderedObjectPostProcessor implements ObjectPostProcessor<String>, Ordered {

		private final int order;

		OrderedObjectPostProcessor(int order) {
			this.order = order;
		}

		public int getOrder() {
			return this.order;
		}

		@SuppressWarnings("unchecked")
		public String postProcess(String object) {
			return object + " " + this.order;
		}

	}

}
