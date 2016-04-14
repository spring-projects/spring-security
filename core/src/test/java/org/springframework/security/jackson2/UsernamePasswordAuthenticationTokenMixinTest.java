package org.springframework.security.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 */
public class UsernamePasswordAuthenticationTokenMixinTest extends AbstractMixinTests {

    @Override
    protected ObjectMapper buildObjectMapper() {
        return super.buildObjectMapper()
                .addMixIn(Collections.unmodifiableSet(Collections.EMPTY_SET).getClass(), UnmodifiableSetMixin.class)
                .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
                .addMixIn(User.class, UserMixin.class)
                .addMixIn(UsernamePasswordAuthenticationToken.class, UsernamePasswordAuthenticationTokenMixin.class);
    }

    @Test
    public void serializeUnauthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws JsonProcessingException, JSONException {
        String expectedJson = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
                " \"principal\": \"user1\", \"credentials\": \"password\", \"authenticated\": false, \"details\": null, " +
                "\"authorities\": [\"java.util.ArrayList\", []], \"name\": \"user1\"}";
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user1", "password");
        String serializedJson = buildObjectMapper().writeValueAsString(token);
        JSONAssert.assertEquals(expectedJson, serializedJson, true);
    }

    @Test
    public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws JsonProcessingException, JSONException {
        String expectedJson = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
                " \"principal\": \"user1\", \"credentials\": \"password\", \"authenticated\": true, \"details\": null, " +
                "\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]], \"name\": \"user1\"}";
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user1", "password", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        String serializedJson = buildObjectMapper().writeValueAsString(token);
        JSONAssert.assertEquals(expectedJson, serializedJson, true);
    }

    @Test
    public void deserializeUnauthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws IOException, JSONException {
        String tokenJson = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
                " \"principal\": \"user1\", \"credentials\": \"password\", \"authenticated\": false, \"details\": null, " +
                "\"authorities\": [\"java.util.ArrayList\", []], \"name\": \"user1\"}";
        UsernamePasswordAuthenticationToken token = buildObjectMapper().readValue(tokenJson, UsernamePasswordAuthenticationToken.class);
        assertThat(token).isNotNull();
        assertThat(token.isAuthenticated()).isEqualTo(false);
        assertThat(token.getAuthorities()).isNotNull().hasSize(0);
    }

    @Test
    public void deserializeAuthenticatedUsernamePasswordAuthenticationTokenMixinTest() throws IOException {
        String tokenJson = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
                "\"principal\": \"user1\", \"credentials\": \"password\", \"authenticated\": true, \"details\": null, " +
                "\"authorities\" : [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
        UsernamePasswordAuthenticationToken token = buildObjectMapper().readValue(tokenJson, UsernamePasswordAuthenticationToken.class);
        assertThat(token).isNotNull();
        assertThat(token.isAuthenticated()).isEqualTo(true);
        assertThat(token.getAuthorities()).isNotNull().hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Test
    public void serializeAuthenticatedUsernamePasswordAuthenticationTokenMixinWithUserTest() throws JsonProcessingException, JSONException {
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        User user = new User("user", "pass", Collections.singleton(authority));
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, "pass", Collections.singleton(authority));
        String expectedJson = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
                "\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"user\", \"password\": \"pass\", \"accountNonExpired\": true, \"enabled\": true, " +
                "\"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\"," +
                "[{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}, \"credentials\": \"pass\"," +
                "\"details\": null, \"name\": \"user\", \"authenticated\": true," +
                "\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
        String actualJson = buildObjectMapper().writeValueAsString(token);
        JSONAssert.assertEquals(expectedJson, actualJson, true);
    }

    @Test
    public void deserializeAuthenticatedUsernamePasswordAuthenticationTokenWithUserTest() throws IOException {
        String tokenJson = "{\"@class\": \"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\"," +
                "\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"user\", \"password\": \"pass\", \"accountNonExpired\": true, \"enabled\": true, " +
                "\"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\"," +
                "[{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}, \"credentials\": \"pass\"," +
                "\"details\": null, \"name\": \"user\", \"authenticated\": true," +
                "\"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}";
        ObjectMapper mapper = buildObjectMapper();
        UsernamePasswordAuthenticationToken token = mapper.readValue(tokenJson, UsernamePasswordAuthenticationToken.class);
        assertThat(token).isNotNull();
        assertThat(token.getPrincipal()).isNotNull().isInstanceOf(User.class);
        assertThat(((User)token.getPrincipal()).getAuthorities()).isNotNull().hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
        assertThat(token.isAuthenticated()).isEqualTo(true);
        assertThat(token.getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
    }
}
