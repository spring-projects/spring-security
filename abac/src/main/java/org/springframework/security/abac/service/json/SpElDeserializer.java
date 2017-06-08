/*
 * Copyright 2017-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.abac.service.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.io.IOException;

/**
 * @author Renato Soppelsa
 * @since 5.0
 */
public class SpElDeserializer extends StdDeserializer<Expression> {

	private ExpressionParser elParser = new SpelExpressionParser();

	public SpElDeserializer(){
		this(null);
	}

	protected SpElDeserializer(Class<?> vc) {
		super(vc);
	}

	@Override
	public Expression deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
		String expressionString = jp.getCodec().readValue(jp, String.class);
		return elParser.parseExpression(expressionString);
	}

}
