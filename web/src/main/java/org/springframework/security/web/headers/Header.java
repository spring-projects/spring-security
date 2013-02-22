package org.springframework.security.web.headers;

import java.util.Arrays;

/**
 * Created with IntelliJ IDEA.
 * User: marten
 * Date: 29-01-13
 * Time: 20:26
 * To change this template use File | Settings | File Templates.
 */
public final class Header {

    private final String name;
    private final String[] values;

    public Header(String name, String... values) {
        this.name = name;
        this.values = values;
    }

    public String getName() {
        return this.name;
    }

    public String[] getValues() {
        return this.values;
    }

    public int hashCode() {
        return name.hashCode() + Arrays.hashCode(values);
    }

    public String toString() {
        return "Header [name: " + name + ", values: " + Arrays.toString(values)+"]";
    }
}
