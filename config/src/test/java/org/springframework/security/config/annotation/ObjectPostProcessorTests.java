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
import java.util.LinkedList;
import java.util.List;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class ObjectPostProcessorTests {

	@Test
	public void convertTypes() {
		assertThat((Object) PerformConversion.perform(new ArrayList<>())).isInstanceOf(LinkedList.class);
	}

	static class ListToLinkedListObjectPostProcessor implements ObjectPostProcessor<List<?>> {

		public <O extends List<?>> O postProcess(O l) {
			return (O) new LinkedList(l);
		}

	}

	static class PerformConversion {

		public static List<?> perform(ArrayList<?> l) {
			return new ListToLinkedListObjectPostProcessor().postProcess(l);
		}

	}

}
