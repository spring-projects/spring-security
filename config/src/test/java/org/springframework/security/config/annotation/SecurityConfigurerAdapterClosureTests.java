/*
 * Copyright 2002-2019 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class SecurityConfigurerAdapterClosureTests {

	ConcereteSecurityConfigurerAdapter conf = new ConcereteSecurityConfigurerAdapter();

	@Test
	public void addPostProcessorClosureWhenPostProcessThenGetsApplied() throws Exception {
		SecurityBuilder<Object> builder = mock(SecurityBuilder.class);
		this.conf.addObjectPostProcessor(new ObjectPostProcessor<List<String>>() {
			@Override
			public <O extends List<String>> O postProcess(O l) {
				l.add("a");
				return l;
			}
		});

		this.conf.init(builder);
		this.conf.configure(builder);

		assertThat(this.conf.list).contains("a");
	}

	static class ConcereteSecurityConfigurerAdapter extends SecurityConfigurerAdapter<Object, SecurityBuilder<Object>> {

		private List<Object> list = new ArrayList<>();

		@Override
		public void configure(SecurityBuilder<Object> builder) throws Exception {
			this.list = postProcess(this.list);
		}

		public ConcereteSecurityConfigurerAdapter list(List<Object> l) {
			this.list = l;
			return this;
		}

	}

}
