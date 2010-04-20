package org.springframework.security.openid;

import java.util.Collections;
import java.util.List;

/**
 * @author Luke Taylor
 * @since 3.1
 */
public class NullAxFetchListFactory implements AxFetchListFactory {
    public List<OpenIDAttribute> createAttributeList(String identifier) {
        return Collections.emptyList();
    }
}
