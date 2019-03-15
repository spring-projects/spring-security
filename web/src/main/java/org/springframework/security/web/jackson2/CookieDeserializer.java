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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.fasterxml.jackson.databind.node.NullNode;

import javax.servlet.http.Cookie;
import java.io.IOException;

/**
 * Jackson deserializer for {@link Cookie}. This is needed because in most cases we don't
 * set {@link Cookie#getDomain()} property. So when jackson deserialize that json {@link Cookie#setDomain(String)}
 * throws {@link NullPointerException}. This is registered with {@link CookieMixin} but you can also use it with
 * your own mixin.
 *
 * @author Jitendra Singh
 * @see CookieMixin
 * @since 4.2
 */
class CookieDeserializer extends JsonDeserializer<Cookie> {

	@Override
	public Cookie deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode jsonNode = mapper.readTree(jp);
		Cookie cookie = new Cookie(readJsonNode(jsonNode, "name").asText(), readJsonNode(jsonNode, "value").asText());
		cookie.setComment(readJsonNode(jsonNode, "comment").asText());
		cookie.setDomain(readJsonNode(jsonNode, "domain").asText());
		cookie.setMaxAge(readJsonNode(jsonNode, "maxAge").asInt(-1));
		cookie.setSecure(readJsonNode(jsonNode, "secure").asBoolean());
		cookie.setVersion(readJsonNode(jsonNode, "version").asInt());
		cookie.setPath(readJsonNode(jsonNode, "path").asText());
		cookie.setHttpOnly(readJsonNode(jsonNode, "httpOnly").asBoolean());
		return cookie;
	}

	private JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return jsonNode.has(field) && !(jsonNode.get(field) instanceof NullNode) ? jsonNode.get(field) : MissingNode.getInstance();
	}
}
