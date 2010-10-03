package org.springframework.security.web.firewall;

import static org.junit.Assert.assertEquals;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class RequestWrapperTests {
    private static Map<String, String> testPaths = new LinkedHashMap<String,String>();

    @BeforeClass
    // Some of these may be unrealistic values, but we can't be sure because of the
    // inconsistency in the spec.
    public static void createTestMap() {
        testPaths.put("/path1;x=y;z=w/path2;x=y/path3;x=y", "/path1/path2/path3");
        testPaths.put("/path1;x=y/path2;x=y/", "/path1/path2/");
        testPaths.put("/path1//path2/", "/path1/path2/");
        testPaths.put("//path1/path2//", "/path1/path2/");
        testPaths.put(";x=y;z=w", "");
    }

    @Test
    public void pathParametersAreRemovedFromServletPath() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        for (Map.Entry<String,String> entry : testPaths.entrySet()) {
            String path = entry.getKey();
            String expectedResult = entry.getValue();
            request.setServletPath(path);
            RequestWrapper wrapper = new RequestWrapper(request);
            assertEquals(expectedResult, wrapper.getServletPath());
            wrapper.reset();
            assertEquals(path, wrapper.getServletPath());
        }
    }

    @Test
    public void pathParametersAreRemovedFromPathInfo() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        for (Map.Entry<String,String> entry : testPaths.entrySet()) {
            String path = entry.getKey();
            String expectedResult = entry.getValue();
            // Should be null when stripped value is empty
            if (expectedResult.length() == 0) {
                expectedResult = null;
            }
            request.setPathInfo(path);
            RequestWrapper wrapper = new RequestWrapper(request);
            assertEquals(expectedResult, wrapper.getPathInfo());
            wrapper.reset();
            assertEquals(path, wrapper.getPathInfo());
        }
    }

}
