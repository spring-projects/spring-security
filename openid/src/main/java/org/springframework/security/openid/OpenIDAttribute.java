package org.springframework.security.openid;

import java.io.Serializable;
import java.util.List;

import org.springframework.util.Assert;

/**
 * Represents an OpenID subject identity attribute.
 * <p>
 * Can be used for configuring the <tt>OpenID4JavaConsumer</tt> with the attributes which should be requested during a
 * fetch request, or to hold values for an attribute which are returned during the authentication process.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class OpenIDAttribute implements Serializable {
    private final String name;
    private final String typeIdentifier;
    private boolean required = false;
    private int count = 1;

    private final List<String> values;

    public OpenIDAttribute(String name, String type) {
        this.name = name;
        this.typeIdentifier = type;
        this.values = null;
    }

    public OpenIDAttribute(String name, String type, List<String> values) {
        Assert.notEmpty(values);
        this.name = name;
        this.typeIdentifier = type;
        this.values = values;
    }

    /**
     * The attribute name
     */
    public String getName() {
        return name;
    }

    /**
     * The attribute type Identifier (a URI).
     */
    public String getType() {
        return typeIdentifier;
    }

    /**
     * The "required" flag for the attribute when used with an authentication request. Defaults to "false".
     */
    public boolean isRequired() {
        return required;
    }

    public void setRequired(boolean required) {
        this.required = required;
    }

    /**
     * The requested count for the attribute when it is used as part of an authentication
     * request. Defaults to 1.
     */
    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    /**
     * The values obtained from an attribute exchange.
     */
    public List<String> getValues() {
        Assert.notNull(values, "Cannot read values from an authentication request attribute");
        return values;
    }

    public String toString() {
        StringBuilder result = new StringBuilder("[");
        result.append(name);
        if (values != null) {
            result.append(":");
            result.append(values.toString());
        }
        result.append("]");
        return result.toString();
    }
}
