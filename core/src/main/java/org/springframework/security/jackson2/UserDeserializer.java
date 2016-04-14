package org.springframework.security.jackson2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.IOException;
import java.util.Set;

/**
 * @author Jitendra Singh
 */
public class UserDeserializer extends JsonDeserializer<User> {

    @Override
    public User deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);
        Set<GrantedAuthority> authorities = mapper.convertValue(jsonNode.get("authorities"), new TypeReference<Set<SimpleGrantedAuthority>>() {
        });
        return new User(
                readJsonNode(jsonNode, "username").asText(), readJsonNode(jsonNode, "password").asText(""),
                readJsonNode(jsonNode, "enabled").asBoolean(), readJsonNode(jsonNode, "accountNonExpired").asBoolean(),
                readJsonNode(jsonNode, "credentialsNonExpired").asBoolean(),
                readJsonNode(jsonNode, "accountNonLocked").asBoolean(), authorities
        );
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
