package sample.dms.secured;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.acegisecurity.acls.MutableAcl;
import org.acegisecurity.acls.MutableAclService;
import org.acegisecurity.acls.domain.BasePermission;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityImpl;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.context.SecurityContextHolder;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;

import sample.dms.AbstractElement;
import sample.dms.DocumentDaoImpl;

/**
 * Adds extra {@link SecureDocumentDao} methods.
 *
 * @author Ben Alex
 * @version $Id$
 *
 */
public class SecureDocumentDaoImpl extends DocumentDaoImpl implements SecureDocumentDao {

    private static final String SELECT_FROM_USERS = "SELECT USERNAME FROM USERS ORDER BY USERNAME";
    private MutableAclService mutableAclService;

    public SecureDocumentDaoImpl(MutableAclService mutableAclService) {
        Assert.notNull(mutableAclService, "MutableAclService required");
        this.mutableAclService = mutableAclService;
    }

    public String[] getUsers() {
        return (String[]) getJdbcTemplate().query(SELECT_FROM_USERS, new RowMapper() {
            public Object mapRow(ResultSet rs, int rowNumber) throws SQLException {
                return rs.getString("USERNAME");
            }
        }).toArray(new String[] {});
    }

    public void create(AbstractElement element) {
        super.create(element);

        // Create an ACL identity for this element
        ObjectIdentity identity = new ObjectIdentityImpl(element);
        MutableAcl acl = mutableAclService.createAcl(identity);

        // If the AbstractElement has a parent, go and retrieve its identity (it should already exist)
        if (element.getParent() != null) {
            ObjectIdentity parentIdentity = new ObjectIdentityImpl(element.getParent());
            MutableAcl aclParent = (MutableAcl) mutableAclService.readAclById(parentIdentity);
            acl.setParent(aclParent);
        }
        acl.insertAce(null, BasePermission.ADMINISTRATION, new PrincipalSid(SecurityContextHolder.getContext().getAuthentication()), true);

        mutableAclService.updateAcl(acl);
    }
}
