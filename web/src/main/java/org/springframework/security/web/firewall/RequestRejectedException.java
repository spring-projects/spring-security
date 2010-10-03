package org.springframework.security.web.firewall;

/**
 * @author Luke Taylor
 */
public class RequestRejectedException extends RuntimeException {
    public RequestRejectedException(String message) {
        super(message);
    }
}
