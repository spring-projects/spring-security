package org.springframework.security.web.headers;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

/**
 * Represents a Header to be added to the {@link HttpServletResponse}
 */
final class Header {

    private final String headerName;
    private final List<String> headerValues;

    /**
     * Creates a new instance
     * @param headerName the name of the header
     * @param headerValues the values of the header
     */
    public Header(String headerName, String... headerValues) {
        Assert.hasText(headerName, "headerName is required");
        Assert.notEmpty(headerValues, "headerValues cannot be null or empty");
        Assert.noNullElements(headerValues, "headerValues cannot contain null values");
        this.headerName = headerName;
        this.headerValues = Arrays.asList(headerValues);
    }

    /**
     * Gets the name of the header. Cannot be <code>null</code>.
     * @return the name of the header.
     */
    public String getName() {
        return this.headerName;
    }

    /**
     * Gets the values of the header. Cannot be null, empty, or contain null
     * values.
     *
     * @return the values of the header
     */
    public List<String> getValues() {
        return this.headerValues;
    }

    public int hashCode() {
        return headerName.hashCode() + headerValues.hashCode();
    }

    public String toString() {
        return "Header [name: " + headerName + ", values: " + headerValues +"]";
    }
}
