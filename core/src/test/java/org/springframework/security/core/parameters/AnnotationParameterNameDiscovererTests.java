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
package org.springframework.security.core.parameters;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.method.P;
import org.springframework.util.ReflectionUtils;

public class AnnotationParameterNameDiscovererTests {
	private AnnotationParameterNameDiscoverer discoverer;

	@Before
	public void setup() {
		discoverer = new AnnotationParameterNameDiscoverer(P.class.getName());
	}

	@Test
	public void getParameterNamesInterfaceSingleParam() {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByTo", String.class))).isEqualTo(
				new String[] { "to" });
	}

	@Test
	public void getParameterNamesInterfaceSingleParamAnnotatedWithMultiParams() {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByToAndFrom", String.class, String.class)))
				.isEqualTo(new String[] { "to", null });
	}

	@Test
	public void getParameterNamesInterfaceNoAnnotation() {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByIdNoAnnotation", String.class))).isNull();
	}

	@Test
	public void getParameterNamesClassSingleParam() {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByTo", String.class))).isEqualTo(
				new String[] { "to" });
	}

	@Test
	public void getParameterNamesClassSingleParamAnnotatedWithMultiParams() {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByToAndFrom", String.class, String.class)))
				.isEqualTo(new String[] { "to", null });
	}

	@Test
	public void getParameterNamesClassNoAnnotation() {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByIdNoAnnotation", String.class))).isNull();
	}

	@Test
	public void getParameterNamesConstructor() throws Exception {
		assertThat(discoverer.getParameterNames(Impl.class.getConstructor(String.class)))
				.isEqualTo(new String[] { "id" });
	}

	@Test
	public void getParameterNamesConstructorNoAnnotation() throws Exception {
		assertThat(discoverer.getParameterNames(Impl.class.getConstructor(Long.class)))
				.isNull();
	}

	@Test
	public void getParameterNamesClassAnnotationOnInterface() throws Exception {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(DaoImpl.class,
						"findMessageByTo", String.class))).isEqualTo(
				new String[] { "to" });
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByTo", String.class))).isEqualTo(
				new String[] { "to" });
	}

	@Test
	public void getParameterNamesClassAnnotationOnImpl() throws Exception {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByToAndFrom", String.class, String.class)))
				.isEqualTo(new String[] { "to", null });
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(DaoImpl.class,
						"findMessageByToAndFrom", String.class, String.class)))
				.isEqualTo(new String[] { "to", "from" });
	}

	@Test
	public void getParameterNamesClassAnnotationOnBaseClass() throws Exception {
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(Dao.class,
						"findMessageByIdNoAnnotation", String.class))).isNull();
		assertThat(
				discoverer.getParameterNames(ReflectionUtils.findMethod(DaoImpl.class,
						"findMessageByIdNoAnnotation", String.class))).isEqualTo(
				new String[] { "id" });
	}

	interface Dao {
		String findMessageByTo(@P("to") String to);

		String findMessageByToAndFrom(@P("to") String to, String from);

		String findMessageByIdNoAnnotation(String id);
	}

	static class BaseDaoImpl {
		public String findMessageByIdNoAnnotation(@P("id") String id) {
			return null;
		}
	}

	static class DaoImpl extends BaseDaoImpl implements Dao {
		public String findMessageByTo(String to) {
			return null;
		}

		public String findMessageByToAndFrom(@P("to") String to, @P("from") String from) {
			return null;
		}
	}

	static class Impl {
		public Impl(Long dataSourceId) {
		}

		public Impl(@P("id") String dataSourceId) {
		}

		String findMessageByTo(@P("to") String to) {
			return null;
		}

		String findMessageByToAndFrom(@P("to") String to, String from) {
			return null;
		}

		String findMessageByIdNoAnnotation(String id) {
			return null;
		}
	}
}
