/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.jackson;

import jakarta.servlet.http.Cookie;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.node.MissingNode;
import tools.jackson.databind.node.NullNode;

/**
 * Jackson deserializer for {@link Cookie}. This is needed because in most cases we don't
 * set {@link Cookie#getDomain()} property. So when jackson deserialize that json
 * {@link Cookie#setDomain(String)} throws {@link NullPointerException}. This is
 * registered with {@link CookieMixin} but you can also use it with your own mixin.
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see CookieMixin
 */
class CookieDeserializer extends ValueDeserializer<Cookie> {

	@Override
	public Cookie deserialize(JsonParser jp, DeserializationContext ctxt) throws JacksonException {
		JsonNode jsonNode = ctxt.readTree(jp);
		Cookie cookie = new Cookie(readJsonNode(jsonNode, "name").stringValue(),
				readJsonNode(jsonNode, "value").stringValue());
		JsonNode domainNode = readJsonNode(jsonNode, "domain");
		cookie.setDomain((domainNode.isMissingNode()) ? null : domainNode.stringValue());
		cookie.setMaxAge(readJsonNode(jsonNode, "maxAge").asInt(-1));
		cookie.setSecure(readJsonNode(jsonNode, "secure").asBoolean());
		JsonNode pathNode = readJsonNode(jsonNode, "path");
		cookie.setPath((pathNode.isMissingNode()) ? null : pathNode.stringValue());
		JsonNode attributes = readJsonNode(jsonNode, "attributes");
		cookie.setHttpOnly(readJsonNode(attributes, "HttpOnly") != null);
		return cookie;
	}

	private JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return hasNonNullField(jsonNode, field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

	private boolean hasNonNullField(JsonNode jsonNode, String field) {
		return jsonNode.has(field) && !(jsonNode.get(field) instanceof NullNode);
	}

}
