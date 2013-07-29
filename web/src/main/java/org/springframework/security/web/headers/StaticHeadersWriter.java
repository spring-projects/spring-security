package org.springframework.security.web.headers;

import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

/**
 * {@code HeaderWriter} implementation which writes the same {@code Header} instance.
 *
 * @author Marten Deinum
 * @author Rob Winch
 * @since 3.2
 */
public class StaticHeadersWriter implements HeaderWriter {

    private final List<Header> headers;

    /**
     * Creates a new instance
     * @param headers the {@link Header} instances to use
     */
    public StaticHeadersWriter(List<Header> headers) {
        Assert.notEmpty(headers,"headers cannot be null or empty");
        this.headers = headers;
    }

    /**
     * Creates a new instance with a single header
     * @param headerName the name of the header
     * @param headerValues the values for the header
     */
    public StaticHeadersWriter(String headerName, String... headerValues) {
        this(Collections.singletonList(new Header(headerName, headerValues)));
    }

    public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        for(Header header : headers) {
            for(String value : header.getValues()) {
                response.addHeader(header.getName(), value);
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getName() + " [headers=" + headers + "]";
    }
}