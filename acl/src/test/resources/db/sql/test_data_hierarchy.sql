--- insert ACL data
INSERT INTO ACL_SID (ID, PRINCIPAL, SID) VALUES
    (10, true, 'user');

INSERT INTO acl_class (id, class, class_id_type) VALUES
    (20,'location','java.lang.String'),
    (21,'org.springframework.security.acls.jdbc.JdbcAclServiceTests$MockLongIdDomainObject','java.lang.Long'),
    (22,'org.springframework.security.acls.jdbc.JdbcAclServiceTests$MockUntypedIdDomainObject',''),
    (23,'costcenter','java.util.UUID');

INSERT INTO acl_object_identity (id, object_id_class, object_id_identity, parent_object, owner_sid, entries_inheriting) VALUES
    (1,20,'US',NULL,10,false),
    (2,20,'US-PAL',1,10,true),
    (3,21,'4711',2,10,true),
    (4,21,'4712',2,10,true),
	(5,22,'5000',3,10,true),
    (6,23,'25d93b3f-c3aa-4814-9d5e-c7c96ced7762',5,10,true);
