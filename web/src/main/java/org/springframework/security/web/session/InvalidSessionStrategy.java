package org.springframework.security.web.session;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Determines the behaviour of the {@code SessionManagementFilter} when an invalid session Id is submitted and
 * detected in the {@code SessionManagementFilter}.
 *
 * @author Luke Taylor
 */
public interface InvalidSessionStrategy {

    void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException;

}
