/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation

import java.util.ArrayList;
import java.util.List;

import spock.lang.Specification

/**
 * @author Rob Winch
 *
 */
class SecurityConfigurerAdapterClosureTests extends Specification {
	ConcereteSecurityConfigurerAdapter conf = new ConcereteSecurityConfigurerAdapter()

	def "addPostProcessor closure"() {
		setup:
			SecurityBuilder<Object> builder = Mock()
			conf.addObjectPostProcessor({ List l ->
				l.add("a")
				l
			} as ObjectPostProcessor<List>)
		when:
			conf.init(builder)
			conf.configure(builder)
		then:
			conf.list.contains("a")
	}

	class ConcereteSecurityConfigurerAdapter extends
			SecurityConfigurerAdapter<Object, SecurityBuilder<Object>> {
		private List<Object> list = new ArrayList<Object>();

		@Override
		public void configure(SecurityBuilder<Object> builder) throws Exception {
			list = postProcess(list);
		}

		public ConcereteSecurityConfigurerAdapter list(List<Object> l) {
			this.list = l;
			return this;
		}
	}
}
