CREATE SCHEMA sa;

CREATE TABLE acl_object_identity (
     id INTEGER NOT NULL GENERATED ALWAYS AS IDENTITY CONSTRAINT acl_object_identity_PK PRIMARY KEY,
     object_identity VARCHAR(250) NOT NULL,
     parent_object INTEGER,
     acl_class VARCHAR(250) NOT NULL,
     CONSTRAINT unique_object_identity UNIQUE(object_identity),
     FOREIGN KEY (parent_object) REFERENCES acl_object_identity(id) ON DELETE CASCADE
);

CREATE TABLE acl_permission (
     id INTEGER NOT NULL GENERATED ALWAYS AS IDENTITY CONSTRAINT acl_permission_PK PRIMARY KEY,
     acl_object_identity INTEGER NOT NULL,
     recipient VARCHAR(100) NOT NULL,
     mask INTEGER NOT NULL,
     CONSTRAINT unique_recipient UNIQUE(acl_object_identity, recipient),
     FOREIGN KEY (acl_object_identity) REFERENCES acl_object_identity(id) ON DELETE CASCADE
);

--INSERT INTO acl_object_identity (object_identity, parent_object, acl_class) VALUES ('org.mydomain.MyClass:1', null, 'org.springframework.security.acl.basic.SimpleAclEntry');
--INSERT INTO acl_object_identity (object_identity, parent_object, acl_class) VALUES ('org.mydomain.MyClass:2', 1, 'org.springframework.security.acl.basic.SimpleAclEntry');
--INSERT INTO acl_object_identity (object_identity, parent_object, acl_class) VALUES ('org.mydomain.MyClass:3', 1, 'org.springframework.security.acl.basic.SimpleAclEntry');
--INSERT INTO acl_object_identity (object_identity, parent_object, acl_class) VALUES ('org.mydomain.MyClass:4', 1, 'org.springframework.security.acl.basic.SimpleAclEntry');
--INSERT INTO acl_object_identity (object_identity, parent_object, acl_class) VALUES ('org.mydomain.MyClass:5', 3, 'org.springframework.security.acl.basic.SimpleAclEntry');
--INSERT INTO acl_object_identity (object_identity, parent_object, acl_class) VALUES ('org.mydomain.MyClass:6', 3, 'org.springframework.security.acl.basic.SimpleAclEntry');

--INSERT INTO acl_permission (acl_object_identity, recipient, mask) VALUES (1, 'ROLE_ADMIN', 1);
--INSERT INTO acl_permission (acl_object_identity, recipient, mask) VALUES (2, 'ROLE_ADMIN', 0);
--INSERT INTO acl_permission (acl_object_identity, recipient, mask) VALUES (2, 'marissa', 2);
--INSERT INTO acl_permission (acl_object_identity, recipient, mask) VALUES (3, 'scott', 14);
--INSERT INTO acl_permission (acl_object_identity, recipient, mask) VALUES (6, 'scott', 1);
