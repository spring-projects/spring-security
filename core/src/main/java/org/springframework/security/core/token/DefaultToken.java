package org.springframework.security.core.token;

import java.util.Date;

import org.springframework.util.Assert;

/**
 * The default implementation of {@link Token}.
 *
 * @author Ben Alex
 * @since 2.0.1
 */
public class DefaultToken implements Token {
    private String key;
    private long keyCreationTime;
    private String extendedInformation;

    public DefaultToken(String key, long keyCreationTime, String extendedInformation) {
        Assert.hasText(key, "Key required");
        Assert.notNull(extendedInformation, "Extended information cannot be null");
        this.key = key;
        this.keyCreationTime = keyCreationTime;
        this.extendedInformation = extendedInformation;
    }

    public String getKey() {
        return key;
    }

    public long getKeyCreationTime() {
        return keyCreationTime;
    }

    public String getExtendedInformation() {
        return extendedInformation;
    }

    public boolean equals(Object obj) {
        if (obj != null && obj instanceof DefaultToken) {
            DefaultToken rhs = (DefaultToken) obj;
            return this.key.equals(rhs.key) && this.keyCreationTime == rhs.keyCreationTime && this.extendedInformation.equals(rhs.extendedInformation);
        }
        return false;
    }

    public int hashCode() {
        int code = 979;
        code = code * key.hashCode();
        code = code * new Long(keyCreationTime).hashCode();
        code = code * extendedInformation.hashCode();
        return code;
    }

    public String toString() {
        return "DefaultToken[key=" + new String(key) + "; creation=" + new Date(keyCreationTime) + "; extended=" + extendedInformation + "]";
    }


}
