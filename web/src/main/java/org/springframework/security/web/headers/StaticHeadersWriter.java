package org.springframework.security.web.headers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

/**
 * {@code HeaderWriter} implementation which writes the same {@code Header} instance.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class StaticHeadersWriter implements HeaderWriter {

    private final Header header;

    public StaticHeadersWriter(String name, String... values) {
        Assert.hasText(name, "Header name is required");
        Assert.notEmpty(values, "Header values cannot be null or empty");
        Assert.noNullElements(values, "Header values cannot contain null values");
        header = new Header(name, values);
    }

    public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        for(String value : header.getValues()) {
            response.addHeader(header.getName(), value);
        }
    }
}
