/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package sample.contact;

/**
 * Iterface for the application's business object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ContactManager {
    //~ Methods ================================================================

    public Contact[] getAllByOwner(String owner);

    public Contact getById(Integer id);

    public Integer getNextId();

    public Contact getRandomContact();

    public void delete(Contact contact);

    public void save(Contact contact);
}
