package org.springframework.security.integration.python;

import org.python.util.PythonInterpreter;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PrePostInvocationAttributeFactory;

public class PythonInterpreterPrePostInvocationAttributeFactory implements PrePostInvocationAttributeFactory{

    public PythonInterpreterPrePostInvocationAttributeFactory() {
        PythonInterpreter.initialize(System.getProperties(), null, new String[] {});
    }


    public PreInvocationAttribute createPreInvocationAttribute(PreFilter preFilter, PreAuthorize preAuthorize) {
        return new PythonInterpreterPreInvocationAttribute(preAuthorize.value());
    }

    public PostInvocationAttribute createPostInvocationAttribute(PostFilter postFilter, PostAuthorize postAuthorize) {
        return null;
    }
}
