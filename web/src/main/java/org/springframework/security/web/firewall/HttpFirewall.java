package org.springframework.security.web.firewall;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Interface which can be used to reject potentially dangerous requests and/or wrap them to
 * control their behaviour.
 * <p>
 * The implementation is injected into the {@code FilterChainProxy} and will be invoked before
 * sending any request through the filter chain. It can also provide a response wrapper if the response
 * behaviour should also be restricted.
 *
 * @author Luke Taylor
 */
public interface HttpFirewall {

    /**
     * Provides the request object which will be passed through the filter chain.
     *
     * @throws RequestRejectedException if the request should be rejected immediately
     */
    FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException;

    /**
     * Provides the response which will be passed through the filter chain.
     *
     * @param response the original response
     * @return either the original response or a replacement/wrapper.
     */
    HttpServletResponse getFirewalledResponse(HttpServletResponse response);
}
