package org.springframework.security.web.context;


import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author Keesun Baik
 */
public class AbstractSecurityWebApplicationInitializerTest {

    @Test
    public void defaultFilterName() {
        assertEquals(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME, "springSecurityFilterChain");
    }

}
