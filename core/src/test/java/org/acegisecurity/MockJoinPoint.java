/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.reflect.CodeSignature;
import org.aspectj.lang.reflect.SourceLocation;

import java.lang.reflect.Method;


/**
 * A mock AspectJ <code>JoinPoint</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockJoinPoint implements JoinPoint {
    //~ Instance fields ========================================================

    private Method beingInvoked;
    private Object object;

    //~ Constructors ===========================================================

    public MockJoinPoint(Object object, Method beingInvoked) {
        this.object = object;
        this.beingInvoked = beingInvoked;
    }

    private MockJoinPoint() {}

    //~ Methods ================================================================

    public Object[] getArgs() {
        throw new UnsupportedOperationException("mock not implemented");
    }

    public String getKind() {
        throw new UnsupportedOperationException("mock not implemented");
    }

    public Signature getSignature() {
        throw new UnsupportedOperationException("mock not implemented");
    }

    public SourceLocation getSourceLocation() {
        throw new UnsupportedOperationException("mock not implemented");
    }

    public StaticPart getStaticPart() {
        return new MockStaticPart(beingInvoked);
    }

    public Object getTarget() {
        return object;
    }

    public Object getThis() {
        throw new UnsupportedOperationException("mock not implemented");
    }

    public String toLongString() {
        throw new UnsupportedOperationException("mock not implemented");
    }

    public String toShortString() {
        throw new UnsupportedOperationException("mock not implemented");
    }

    //~ Inner Classes ==========================================================

    private class MockCodeSignature implements CodeSignature {
        private Method beingInvoked;

        public MockCodeSignature(Method beingInvoked) {
            this.beingInvoked = beingInvoked;
        }

        private MockCodeSignature() {}

        public Class getDeclaringType() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public String getDeclaringTypeName() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public Class[] getExceptionTypes() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public int getModifiers() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public String getName() {
            return beingInvoked.getName();
        }

        public String[] getParameterNames() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public Class[] getParameterTypes() {
            return beingInvoked.getParameterTypes();
        }

        public String toLongString() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public String toShortString() {
            throw new UnsupportedOperationException("mock not implemented");
        }
    }

    private class MockStaticPart implements StaticPart {
        private Method beingInvoked;

        public MockStaticPart(Method beingInvoked) {
            this.beingInvoked = beingInvoked;
        }

        private MockStaticPart() {}

        public String getKind() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public Signature getSignature() {
            return new MockCodeSignature(beingInvoked);
        }

        public SourceLocation getSourceLocation() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public String toLongString() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public String toShortString() {
            throw new UnsupportedOperationException("mock not implemented");
        }
    }
}
