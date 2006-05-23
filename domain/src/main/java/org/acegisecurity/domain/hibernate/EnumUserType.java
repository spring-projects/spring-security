/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity.domain.hibernate;

import org.acegisecurity.domain.util.GenericsUtils;

import org.hibernate.HibernateException;

import org.hibernate.usertype.UserType;

import java.io.Serializable;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;


/**
 * Java 1.5 <code>enum</code>eration compatible Hibernate 3 <code>UserType</code>.
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @param <E> DOCUMENT ME!
 */
public class EnumUserType<E extends Enum<E>> implements UserType {
    //~ Static fields/initializers =====================================================================================

    private static final int[] SQL_TYPES = {Types.VARCHAR};

    //~ Instance fields ================================================================================================

    private Class<E> clazz = null;

    //~ Constructors ===================================================================================================

    @SuppressWarnings("unchecked")
    protected EnumUserType() {
        this.clazz = GenericsUtils.getGeneric(getClass());
    }

    //~ Methods ========================================================================================================

    public Object assemble(Serializable cached, Object owner)
        throws HibernateException {
        return cached;
    }

    public Object deepCopy(Object value) throws HibernateException {
        return value;
    }

    public Serializable disassemble(Object value) throws HibernateException {
        return (Serializable) value;
    }

    public boolean equals(Object x, Object y) throws HibernateException {
        if (x == y) {
            return true;
        }

        if ((null == x) || (null == y)) {
            return false;
        }

        return x.equals(y);
    }

    public int hashCode(Object x) throws HibernateException {
        return x.hashCode();
    }

    public boolean isMutable() {
        return false;
    }

    public Object nullSafeGet(ResultSet resultSet, String[] names, Object owner)
        throws HibernateException, SQLException {
        String name = resultSet.getString(names[0]);
        E result = null;

        if (!resultSet.wasNull()) {
            result = Enum.valueOf(clazz, name);
        }

        return result;
    }

    public void nullSafeSet(PreparedStatement preparedStatement, Object value, int index)
        throws HibernateException, SQLException {
        if (null == value) {
            preparedStatement.setNull(index, Types.VARCHAR);
        } else {
            preparedStatement.setString(index, ((Enum) value).name());
        }
    }

    public Object replace(Object original, Object target, Object owner)
        throws HibernateException {
        return original;
    }

    public Class returnedClass() {
        return clazz;
    }

    public int[] sqlTypes() {
        return SQL_TYPES;
    }
}
