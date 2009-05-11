package org.springframework.security.integration.python;

import org.springframework.security.access.prepost.PreInvocationAttribute;

public class PythonInterpreterPreInvocationAttribute implements PreInvocationAttribute {
    private String script;

    PythonInterpreterPreInvocationAttribute(String script) {
        this.script = script;
    }

    public String getAttribute() {
        return null;
    }

    public String getScript() {
        return script;
    }
}
