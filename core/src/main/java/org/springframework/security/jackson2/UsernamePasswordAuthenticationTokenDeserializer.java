package org.springframework.security.jackson2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.IOException;
import java.util.List;

/**
 * @author Jitendra Singh
 */
public class UsernamePasswordAuthenticationTokenDeserializer extends JsonDeserializer<UsernamePasswordAuthenticationToken> {

    @Override
    public UsernamePasswordAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        UsernamePasswordAuthenticationToken token = null;
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);
        Boolean authenticated = readJsonNode(jsonNode, "authenticated").asBoolean();
        JsonNode principalNode = readJsonNode(jsonNode, "principal");
        Object principal = null;
        if(principalNode.isObject()) {
            principal = mapper.readValue(principalNode.toString(), new TypeReference<User>() {});
        } else {
            principal = principalNode.asText();
        }
        Object credentials = readJsonNode(jsonNode, "credentials").asText();
        List<GrantedAuthority> authorities = mapper.readValue(
                readJsonNode(jsonNode, "authorities").toString(), new TypeReference<List<GrantedAuthority>>() {
        });
        if (authenticated) {
            token = new UsernamePasswordAuthenticationToken(principal, credentials, authorities);
        } else {
            token = new UsernamePasswordAuthenticationToken(principal, credentials);
        }
        token.setDetails(readJsonNode(jsonNode, "details"));
        return token;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
