/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.client.jackson2;

import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.util.StdConverter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;

public class StdConvertersTests {

	private final StdConverter<JsonNode, ClientAuthenticationMethod> clientAuthenticationMethodConverter = new StdConverters.ClientAuthenticationMethodConverter();

	@ParameterizedTest
	@MethodSource("convertWhenClientAuthenticationMethodConvertedThenDeserializes")
	void convertWhenClientAuthenticationMethodConvertedThenDeserializes(String clientAuthenticationMethod) {
		ObjectNode jsonNode = JsonNodeFactory.instance.objectNode();
		jsonNode.put("value", clientAuthenticationMethod);
		ClientAuthenticationMethod actual = this.clientAuthenticationMethodConverter.convert(jsonNode);
		assertThat(actual.getValue()).isEqualTo(clientAuthenticationMethod);
	}

	static Stream<Arguments> convertWhenClientAuthenticationMethodConvertedThenDeserializes() {
		return Stream.of(Arguments.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()),
				Arguments.of(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()),
				Arguments.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()),
				Arguments.of(ClientAuthenticationMethod.NONE.getValue()), Arguments.of("custom_method"));
	}

}
