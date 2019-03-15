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
package org.springframework.security.web.util;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;

/**
 *
 * @author Luke Taylor
 */
public class UrlUtilsTests {

	@Test
	public void absoluteUrlsAreMatchedAsAbsolute() throws Exception {
		assertThat(UrlUtils.isAbsoluteUrl("http://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("http1://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("HTTP://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("https://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("a://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("zz+zz.zz-zz://something/")).isTrue();
	}

}
