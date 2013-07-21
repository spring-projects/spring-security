package org.springframework.security.web.firewall;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Request wrapper which is returned by the {@code HttpFirewall} interface.
 * <p>
 * The only difference is the {@code reset} method which allows some
 * or all of the state to be reset by the {@code FilterChainProxy} when the
 * request leaves the security filter chain.
 *
 * @author Luke Taylor
 */
public abstract class FirewalledRequest extends HttpServletRequestWrapper {
    /**
     * Constructs a request object wrapping the given request.
     *
     * @throws IllegalArgumentException if the request is null
     */
    public FirewalledRequest(HttpServletRequest request) {
        super(request);
    }

    /**
     * This method will be called once the request has passed through the
     * security filter chain, when it is about to proceed to the application
     * proper.
     * <p>
     * An implementation can thus choose to modify the state of the request
     * for the security infrastructure, while still maintaining the original
     * {@link HttpServletRequest}.
     */
    public abstract void reset();

    @Override
    public String toString() {
        return "FirewalledRequest[ " + getRequest() + "]";
    }
}
