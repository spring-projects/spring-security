package org.springframework.security.intercept.web;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class RequestKey {
    private String url;
    private String method;

    public RequestKey(String url) {
        this(url, null);
    }

    public RequestKey(String url, String method) {
        this.url = url;
        this.method = method;
    }
    
    String getUrl() {
        return url;
    }

    String getMethod() {
        return method;
    }

    public int hashCode() {
        int code = 31;
        code ^= url.hashCode();
        
        if (method != null) {
            code ^= method.hashCode();
        }

        return code;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof RequestKey)) {
            return false;
        }

        RequestKey key = (RequestKey) obj;

        if (!url.equals(key.url)) {
            return false;
        }
        
        if (method == null) {
            return key.method == null;
        }

        return method.equals(key.method);        
    }

    public String toString() {
        StringBuffer sb = new StringBuffer(url.length() + 7);
        sb.append("[");
        if (method != null) {
            sb.append(method).append(",");
        }
        sb.append(url);
        sb.append("]");
        
        return sb.toString();
    }
}
