package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.io.IOException;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Jitendra Singh
 */
@RunWith(MockitoJUnitRunner.class)
public class WebAuthenticationDetailsMixinTest {

    ObjectMapper mapper;

    @Before
    public void setup() {
        mapper = new ObjectMapper()
                .addMixIn(WebAuthenticationDetails.class, WebAuthenticationDetailsMixin.class);
    }

    @Test
    public void buildWebAuthenticationDetailsUsingDifferentConstructors() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("localhost");
        request.setSession(new MockHttpSession(null, "1"));

        WebAuthenticationDetails details = new WebAuthenticationDetails(request);
        String jsonString = "{\"@class\": \"org.springframework.security.web.authentication.WebAuthenticationDetails\"," +
                "\"sessionId\": \"1\", \"remoteAddress\": \"/localhost\"}";
        WebAuthenticationDetails authenticationDetails = mapper.readValue(jsonString, WebAuthenticationDetails.class);
        assertThat(details.equals(authenticationDetails));
    }

    @Test
    public void webAuthenticationDetailsSerializeTest() throws JsonProcessingException, JSONException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("/home");
        request.setSession(new MockHttpSession(null, "1"));
        WebAuthenticationDetails details = new WebAuthenticationDetails(request);
        String expectedJson = "{\"@class\": \"org.springframework.security.web.authentication.WebAuthenticationDetails\"," +
                "\"sessionId\": \"1\", \"remoteAddress\": \"/home\"}";
        String actualJson = mapper.writeValueAsString(details);
        JSONAssert.assertEquals(expectedJson, actualJson, true);
    }

    @Test
    public void webAuthenticationDetailsDeserializeTest() throws IOException, JSONException {
        String actualJson = "{\"@class\": \"org.springframework.security.web.authentication.WebAuthenticationDetails\"," +
                "\"sessionId\": \"1\", \"remoteAddress\": \"/home\"}";
        WebAuthenticationDetails details = mapper.readValue(actualJson, WebAuthenticationDetails.class);
        assertThat(details).isNotNull();
        assertThat(details.getRemoteAddress()).isEqualTo("/home");
        assertThat(details.getSessionId()).isEqualTo("1");
    }
}
