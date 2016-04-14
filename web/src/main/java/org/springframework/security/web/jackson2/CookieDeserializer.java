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
 * @author Jitendra Singh
 */
public class CookieDeserializer extends JsonDeserializer<Cookie> {

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
        cookie.setHttpOnly(readJsonNode(jsonNode, "isHttpOnly").asBoolean());
        return cookie;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) && !(jsonNode.get(field) instanceof NullNode) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
