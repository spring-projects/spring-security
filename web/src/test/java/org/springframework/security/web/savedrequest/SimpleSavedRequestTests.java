/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.savedrequest;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class SimpleSavedRequestTests {

	@Test
	public void constructorWhenGivenSavedRequestThenCopies() {
		SavedRequest savedRequest = new SimpleSavedRequest(prepareSavedRequest());
		assertThat(savedRequest.getMethod()).isEqualTo("POST");
		List<Cookie> cookies = savedRequest.getCookies();
		assertThat(cookies).hasSize(1);
		Cookie cookie = cookies.get(0);
		assertThat(cookie.getName()).isEqualTo("cookiename");
		assertThat(cookie.getValue()).isEqualTo("cookievalue");
		Collection<String> headerNames = savedRequest.getHeaderNames();
		assertThat(headerNames).hasSize(1);
		String headerName = headerNames.iterator().next();
		assertThat(headerName).isEqualTo("headername");
		List<String> headerValues = savedRequest.getHeaderValues("headername");
		assertThat(headerValues).hasSize(1);
		String headerValue = headerValues.get(0);
		assertThat(headerValue).isEqualTo("headervalue");
		List<Locale> locales = savedRequest.getLocales();
		assertThat(locales).hasSize(1);
		Locale locale = locales.get(0);
		assertThat(locale).isEqualTo(Locale.ENGLISH);
		Map<String, String[]> parameterMap = savedRequest.getParameterMap();
		assertThat(parameterMap).hasSize(1);
		String[] values = parameterMap.get("key");
		assertThat(values).hasSize(1);
		assertThat(values[0]).isEqualTo("value");
	}

	@Test
	public void constructorWhenGivenRedirectUrlThenDefaultValues() {
		SavedRequest savedRequest = new SimpleSavedRequest("redirectUrl");
		assertThat(savedRequest.getMethod()).isEqualTo("GET");
		assertThat(savedRequest.getCookies()).isEmpty();
		assertThat(savedRequest.getHeaderNames()).isEmpty();
		assertThat(savedRequest.getHeaderValues("headername")).isEmpty();
		assertThat(savedRequest.getLocales()).isEmpty();
		assertThat(savedRequest.getParameterMap()).isEmpty();
	}

	private SimpleSavedRequest prepareSavedRequest() {
		SimpleSavedRequest simpleSavedRequest = new SimpleSavedRequest("redirectUrl");
		simpleSavedRequest.setCookies(Collections.singletonList(new Cookie("cookiename", "cookievalue")));
		simpleSavedRequest.setMethod("POST");
		simpleSavedRequest.setHeaders(Collections.singletonMap("headername", Collections.singletonList("headervalue")));
		simpleSavedRequest.setLocales(Collections.singletonList(Locale.ENGLISH));
		simpleSavedRequest.setParameters(Collections.singletonMap("key", new String[] { "value" }));
		return simpleSavedRequest;
	}

}
