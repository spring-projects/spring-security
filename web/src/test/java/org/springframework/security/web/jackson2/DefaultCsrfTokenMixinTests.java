package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultCsrfTokenMixinTests {

    ObjectMapper objectMapper;
    String defaultCsrfTokenJson;

    @Before
    public void setup() {
        objectMapper = new ObjectMapper();
        objectMapper.addMixIn(DefaultCsrfToken.class, DefaultCsrfTokenMixin.class);
        defaultCsrfTokenJson = "{\"@class\": \"org.springframework.security.web.csrf.DefaultCsrfToken\", " +
                "\"headerName\": \"csrf-header\", \"parameterName\": \"_csrf\", \"token\": \"1\"}";
    }

    @Test
    public void defaultCsrfTokenSerializedTest() throws JsonProcessingException, JSONException {
        DefaultCsrfToken token = new DefaultCsrfToken("csrf-header", "_csrf", "1");
        String serializedJson = objectMapper.writeValueAsString(token);
        JSONAssert.assertEquals(defaultCsrfTokenJson, serializedJson, true);
    }

    @Test
    public void defaultCsrfTokenDeserializeTest() throws IOException {
        DefaultCsrfToken token = objectMapper.readValue(defaultCsrfTokenJson, DefaultCsrfToken.class);
        assertThat(token).isNotNull();
        assertThat(token.getHeaderName()).isEqualTo("csrf-header");
        assertThat(token.getParameterName()).isEqualTo("_csrf");
        assertThat(token.getToken()).isEqualTo("1");
    }

    @Test(expected = JsonMappingException.class)
    public void defaultCsrfTokenDeserializeWithoutClassTest() throws IOException {
        String tokenJson = "{\"headerName\": \"csrf-header\", \"parameterName\": \"_csrf\", \"token\": \"1\"}";
        objectMapper.readValue(tokenJson, DefaultCsrfToken.class);
    }

    @Test(expected = JsonMappingException.class)
    public void defaultCsrfTokenDeserializeNullValuesTest() throws IOException {
        String tokenJson = "{\"@class\": \"org.springframework.security.web.csrf.DefaultCsrfToken\", \"headerName\": \"\", \"parameterName\": null, \"token\": \"1\"}";
        objectMapper.readValue(tokenJson, DefaultCsrfToken.class);
    }
}
