/*
 * Copyright 2002-2012 the original author or authors.
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
package org.springframework.security.config.http;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareOnlyThisForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import org.springframework.beans.factory.xml.ParserContext;

import static org.mockito.Mockito.verifyZeroInteractions;

@RunWith(PowerMockRunner.class)
@PrepareOnlyThisForTest(ParserContext.class)
public class WebConfigUtilsTests {

	public final static String URL = "/url";

	@Mock
	private ParserContext parserContext;

	// SEC-1980
	@Test
	public void validateHttpRedirectSpELNoParserWarning() {
		WebConfigUtils.validateHttpRedirect("#{T(org.springframework.security.config.http.WebConfigUtilsTest).URL}",
				parserContext, "fakeSource");
		verifyZeroInteractions(parserContext);
	}

}