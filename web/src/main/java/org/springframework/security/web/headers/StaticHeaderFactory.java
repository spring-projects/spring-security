package org.springframework.security.web.headers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

/**
 * {@code HeaderFactory} implementation which returns the same {@code Header} instance.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class StaticHeaderFactory implements HeaderFactory {

    private final Header header;

    public StaticHeaderFactory(String name, String... values) {
        Assert.hasText(name, "Header name is required");
        Assert.notEmpty(values, "Header values cannot be null or empty");
        Assert.noNullElements(values, "Header values cannot contain null values");
        header = new Header(name, values);
    }

    public Header create(HttpServletRequest request, HttpServletResponse response) {
        return header;
    }
}
