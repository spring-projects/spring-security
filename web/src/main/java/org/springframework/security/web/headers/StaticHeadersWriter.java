package org.springframework.security.web.headers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@code HeaderWriter} implementation which writes the same {@code Header} instance.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class StaticHeadersWriter implements HeaderWriter {

    private final Header header;

    /**
     * Creates a new instance
     * @param headerName the name of the header
     * @param headerValues the values for the header
     */
    public StaticHeadersWriter(String headerName, String... headerValues) {
        header = new Header(headerName, headerValues);
    }

    public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        for(String value : header.getValues()) {
            response.addHeader(header.getName(), value);
        }
    }
}