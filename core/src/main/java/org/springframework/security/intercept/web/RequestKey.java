package org.springframework.security.intercept.web;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class RequestKey {
    String url;
    String method;

    public RequestKey(String url) {
        this(url, "");
    }

    public RequestKey(String url, String method) {
        this.url = url;
        this.method = method;
    }

    public int hashCode() {
        int code = 31;
        code ^= url.hashCode();
        code ^= method.hashCode();

        return code;

    }

    public boolean equals(Object obj) {
        if (!(obj instanceof RequestKey)) {
            return false;
        }

        RequestKey key = (RequestKey) obj;

        return url.equals(key.url) && method.equals(key.method);        
    }
}
