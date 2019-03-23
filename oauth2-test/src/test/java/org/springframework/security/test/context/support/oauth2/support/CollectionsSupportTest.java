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
package org.springframework.security.test.context.support.oauth2.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.context.support.oauth2.support.CollectionsSupport.nullIfEmpty;
import static org.springframework.security.test.context.support.oauth2.support.CollectionsSupport.putIfNotEmpty;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.junit.Test;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public class CollectionsSupportTest {

	@Test
	public void nullIfEmptyReturnsNullForNullString() {
		assertThat(nullIfEmpty(null)).isNull();
	}

	@Test
	public void nullIfEmptyReturnsNullForEmptyString() {
		assertThat(nullIfEmpty("")).isNull();
	}

	@Test
	public void nullIfEmptyReturnsNonNullForSpace() {
		assertThat(nullIfEmpty(" ")).isEqualTo(" ");
	}

	@Test
	public void nullIfEmptyReturnsNonNullForToto() {
		assertThat(nullIfEmpty("Toto")).isEqualTo("Toto");
	}

	@Test
	public void putIfNotEmptyDoesNothingForNullString() {
		assertThat(putIfNotEmpty("foo", (String) null, new HashMap<>())).isEmpty();
	}

	@Test
	public void putIfNotEmptyDoesNothingForEmptyString() {
		assertThat(putIfNotEmpty("foo", "", new HashMap<>())).isEmpty();
	}

	@Test
	public void putIfNotEmptyInsertsSpace() {
		assertThat(putIfNotEmpty("foo", " ", new HashMap<>()).get("foo")).isEqualTo(" ");
	}

	@Test
	public void putIfNotEmptyInsertsToto() {
		assertThat(putIfNotEmpty("foo", "Toto", new HashMap<>()).get("foo")).isEqualTo("Toto");
	}

	@Test
	public void putIfNotEmptyDoesNothingForNullList() {
		assertThat(putIfNotEmpty("foo", (List<String>) null, new HashMap<>())).isEmpty();
	}

	@Test
	public void putIfNotEmptyDoesNothingForEmptyList() {
		assertThat(putIfNotEmpty("foo", Collections.emptyList(), new HashMap<>())).isEmpty();
	}

	@Test
	public void putIfNotEmptyInsertsNonEmptyList() {
		@SuppressWarnings("unchecked")
		final List<String> actual =
				(List<String>) (putIfNotEmpty("foo", Collections.singletonList("Toto"), new HashMap<>()).get("foo"));
		assertThat(actual).hasSize(1);
		assertThat(actual).contains("Toto");
	}

}
