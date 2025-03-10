/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;

import java.io.IOException;

/**
 * Jackson deserializer for {@link ResidentKeyRequirement}
 *
 * @author Justin Cranford
 * @since 6.5
 */
@SuppressWarnings("serial")
public class ResidentKeyRequirementDeserializer extends StdDeserializer<ResidentKeyRequirement> {

    public ResidentKeyRequirementDeserializer() {
        super(ResidentKeyRequirement.class);
    }

    @Override
    public ResidentKeyRequirement deserialize(JsonParser parser, DeserializationContext ctxt)
			throws IOException {
		String type = parser.readValueAs(String.class);
		return ResidentKeyRequirement.valueOf(type);
    }
}
