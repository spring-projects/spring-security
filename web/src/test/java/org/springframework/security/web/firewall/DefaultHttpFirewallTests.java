package org.springframework.security.web.firewall;

import static org.junit.Assert.fail;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Luke Taylor
 */
public class DefaultHttpFirewallTests {
    public String[] unnormalizedPaths = {
            "/..",
            "/./path/",
            "/path/path/.",
            "/path/path//.",
            "./path/../path//.",
            "./path",
            ".//path",
            "."
    };

    @Test
    public void unnormalizedPathsAreRejected() throws Exception {
        DefaultHttpFirewall fw = new DefaultHttpFirewall();

        MockHttpServletRequest request;
        for (String path : unnormalizedPaths) {
            request = new MockHttpServletRequest();
            request.setServletPath(path);
            try {
                fw.getFirewalledRequest(request);
                fail(path + " is un-normalized");
            } catch (RequestRejectedException expected) {
            }
            request.setPathInfo(path);
            try {
                fw.getFirewalledRequest(request);
                fail(path + " is un-normalized");
            } catch (RequestRejectedException expected) {
            }
        }
    }
}
