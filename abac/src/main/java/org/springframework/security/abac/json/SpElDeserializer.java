package org.springframework.security.abac.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.io.IOException;

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
