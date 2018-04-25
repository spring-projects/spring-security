package org.springframework.security.oauth2.client.util;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Created by XYUU on 2018/4/24.
 */
public final class AccessTokenResponseJackson2Deserializer extends StdDeserializer<OAuth2AccessTokenResponse> {

    public AccessTokenResponseJackson2Deserializer() {
        super(OAuth2AccessTokenResponse.class);
    }

    @Override
    public OAuth2AccessTokenResponse deserialize(JsonParser jp, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        String tokenValue = null;
        String tokenType = null;
        String refreshToken = null;
        Long expiresIn = 0L;
        Set<String> scope = null;
        Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();

        // TODO What should occur if a parameter exists twice
        while (jp.nextToken() != JsonToken.END_OBJECT) {
            String name = jp.getCurrentName();
            jp.nextToken();
            switch (name) {
                case "access_token":
                    tokenValue = jp.getText();
                    break;
                case "token_type":
                    tokenType = jp.getText();
                    break;
                case "refresh_token":
                    refreshToken = jp.getText();
                    break;
                case "expires_in":
                    try {
                        expiresIn = jp.getLongValue();
                    } catch (JsonParseException e) {
                        expiresIn = Long.valueOf(jp.getText());
                    }
                    break;
                case "scope":
                    scope = parseScope(jp);
                    break;
                default:
                    additionalInformation.put(name, jp.readValueAs(Object.class));
            }
        }
        // TODO What should occur if a required parameter (tokenValue or tokenType) is missing?
        return OAuth2AccessTokenResponse.withToken(tokenValue)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(expiresIn)
                .scopes(scope)
                .additionalParameters(additionalInformation).build();
    }

    private Set<String> parseScope(JsonParser jp) throws JsonParseException, IOException {
        Set<String> scope;
        if (jp.getCurrentToken() == JsonToken.START_ARRAY) {
            scope = new TreeSet<>();
            while (jp.nextToken() != JsonToken.END_ARRAY) {
                scope.add(jp.getValueAsString());
            }
        } else {
            String text = jp.getText();
            scope = OAuth2Utils.parseParameterList(text);
        }
        return scope;
    }
}
