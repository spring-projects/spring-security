/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;

import org.springframework.security.jackson2.SecurityJackson2Modules;

/**
 * @author Jitenra Singh
 * @since 4.2
 */
public abstract class AbstractMixinTests {

	protected ObjectMapper mapper;

	@Before
	public void setup() {
		mapper = new ObjectMapper();
		ClassLoader loader = getClass().getClassLoader();
		mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

}
