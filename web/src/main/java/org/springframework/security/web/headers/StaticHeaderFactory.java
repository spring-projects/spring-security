package org.springframework.security.web.headers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@code HeaderFactory} implementation which returns the same {@code Header} instance.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class StaticHeaderFactory implements HeaderFactory {

    private final Header header;

    public StaticHeaderFactory(String name, String... values) {
        header = new Header(name, values);
    }

    public Header create(HttpServletRequest request, HttpServletResponse response) {
        return header;
    }
}
