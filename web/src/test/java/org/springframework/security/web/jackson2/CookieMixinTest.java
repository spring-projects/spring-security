package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import javax.servlet.http.Cookie;
import java.io.IOException;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Jitendra Singh
 */
public class CookieMixinTest {

    ObjectMapper buildObjectMapper() {
        return new ObjectMapper()
                .addMixIn(Cookie.class, CookieMixin.class);
    }

    @Test
    public void serializeCookie() throws JsonProcessingException, JSONException {
        Cookie cookie = new Cookie("demo", "cookie1");
        String expectedString = "{\"@class\": \"javax.servlet.http.Cookie\", \"name\": \"demo\", \"value\": \"cookie1\"," +
                "\"comment\": null, \"maxAge\": -1, \"path\": null, \"secure\": false, \"version\": 0, \"isHttpOnly\": false, \"domain\": null}";
        String actualString = buildObjectMapper().writeValueAsString(cookie);
        JSONAssert.assertEquals(expectedString, actualString, true);
    }

    @Test
    public void deserializeCookie() throws IOException {
        String cookieString = "{\"@class\": \"javax.servlet.http.Cookie\", \"name\": \"demo\", \"value\": \"cookie1\"," +
                "\"comment\": null, \"maxAge\": -1, \"path\": null, \"secure\": false, \"version\": 0, \"isHttpOnly\": false, \"domain\": null}";
        Cookie cookie = buildObjectMapper().readValue(cookieString, Cookie.class);
        assertThat(cookie).isNotNull();
        assertThat(cookie.getName()).isEqualTo("demo");
        assertThat(cookie.getDomain()).isEqualTo("");
        assertThat(cookie.isHttpOnly()).isEqualTo(false);
    }
}
