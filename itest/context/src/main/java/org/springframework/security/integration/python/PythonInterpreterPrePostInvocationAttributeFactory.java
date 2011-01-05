package org.springframework.security.integration.python;

import org.python.util.PythonInterpreter;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PrePostInvocationAttributeFactory;

public class PythonInterpreterPrePostInvocationAttributeFactory implements PrePostInvocationAttributeFactory{

    public PythonInterpreterPrePostInvocationAttributeFactory() {
        PythonInterpreter.initialize(System.getProperties(), null, new String[] {});
    }


    public PreInvocationAttribute createPreInvocationAttribute(String preFilterAttribute, String filterObject, String preAuthorizeAttribute) {
        return new PythonInterpreterPreInvocationAttribute(preAuthorizeAttribute    );
    }

    public PostInvocationAttribute createPostInvocationAttribute(String postFilterAttribute, String postAuthorizeAttribute) {
        return null;
    }
}
