package org.springframework.security.integration.python;

import org.springframework.security.access.prepost.PreAuthorize;

public interface TestService {

    @PreAuthorize("someMethod.py")
    public void someMethod();

}
