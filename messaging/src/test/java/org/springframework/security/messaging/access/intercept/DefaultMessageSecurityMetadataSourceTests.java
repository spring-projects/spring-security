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
package org.springframework.security.messaging.access.intercept;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.messaging.Message;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DefaultMessageSecurityMetadataSourceTests {
	@Mock
	MessageMatcher<Object> matcher1;
	@Mock
	MessageMatcher<Object> matcher2;
	@Mock
	Message<?> message;
	@Mock
	Authentication authentication;

	SecurityConfig config1;

	SecurityConfig config2;

	LinkedHashMap<MessageMatcher<?>, Collection<ConfigAttribute>> messageMap;

	MessageSecurityMetadataSource source;

	@Before
	public void setup() {
		messageMap = new LinkedHashMap<MessageMatcher<?>, Collection<ConfigAttribute>>();
		messageMap.put(matcher1, Arrays.<ConfigAttribute> asList(config1));
		messageMap.put(matcher2, Arrays.<ConfigAttribute> asList(config2));

		source = new DefaultMessageSecurityMetadataSource(messageMap);
	}

	@Test
	public void getAttributesNull() {
		assertThat(source.getAttributes(message)).isNull();
	}

	@Test
	public void getAttributesFirst() {
		when(matcher1.matches(message)).thenReturn(true);

		assertThat(source.getAttributes(message)).containsOnly(config1);
	}

	@Test
	public void getAttributesSecond() {
		when(matcher1.matches(message)).thenReturn(true);

		assertThat(source.getAttributes(message)).containsOnly(config2);
	}

	@Test
	public void getAllConfigAttributes() {
		assertThat(source.getAllConfigAttributes()).containsOnly(config1, config2);
	}

	@Test
	public void supportsFalse() {
		assertThat(source.supports(Object.class)).isFalse();
	}

	@Test
	public void supportsTrue() {
		assertThat(source.supports(Message.class)).isTrue();
	}
}
