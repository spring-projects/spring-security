package org.springframework.security.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Jitendra Singh
 */
public class SecurityContextMixinTest extends AbstractMixinTests {

    @Override
    protected ObjectMapper buildObjectMapper() {
        return super.buildObjectMapper()
                .addMixIn(UsernamePasswordAuthenticationToken.class, UsernamePasswordAuthenticationTokenMixin.class)
                .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class);
    }

    @Test
    public void securityContextSerializeTest() throws JsonProcessingException, JSONException {
        String expectedJson = "{\"@class\": \"org.springframework.security.core.context.SecurityContextImpl\", \"authentication\": " +
                    "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
                        "\"principal\": \"user\", \"credentials\": \"password\", \"authenticated\": true, \"details\": null, \"name\": \"user\"," +
                        "\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]" +
                    "}" +
                "}";
        SecurityContext context = new SecurityContextImpl();
        context.setAuthentication(new UsernamePasswordAuthenticationToken("user", "password", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))));
        String actualJson = buildObjectMapper().writeValueAsString(context);
        JSONAssert.assertEquals(expectedJson, actualJson, true);
    }

    @Test
    public void securityContextDeserializeTest() throws IOException {
        String contextJson = "{\"@class\": \"org.springframework.security.core.context.SecurityContextImpl\", \"authentication\": " +
                "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
                    "\"principal\": \"user\", \"credentials\": \"password\", \"authenticated\": true, \"details\": null, \"name\": \"user\"," +
                    "\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]" +
                    "}" +
                "}";
        SecurityContext context = buildObjectMapper().readValue(contextJson, SecurityContextImpl.class);
        assertThat(context).isNotNull();
        assertThat(context.getAuthentication()).isNotNull().isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(context.getAuthentication().getPrincipal()).isEqualTo("user");
        assertThat(context.getAuthentication().getCredentials()).isEqualTo("password");
        assertThat(context.getAuthentication().isAuthenticated()).isEqualTo(true);
        assertThat(context.getAuthentication().getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
    }
}
