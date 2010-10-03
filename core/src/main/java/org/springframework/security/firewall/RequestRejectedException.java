package org.springframework.security.firewall;

/**
 * @author Luke Taylor
 */
public class RequestRejectedException extends RuntimeException {
    public RequestRejectedException(String message) {
        super(message);
    }
}
