-- ACL Schema SQL for Oracle Database 10g+

-- drop trigger acl_sid_id_trigger;
-- drop trigger acl_class_id_trigger;
-- drop trigger acl_object_identity_id_trigger;
-- drop trigger acl_entry_id_trigger;
-- drop sequence acl_sid_sequence;
-- drop sequence acl_class_sequence;
-- drop sequence acl_object_identity_sequence;
-- drop sequence acl_entry_sequence;
-- drop table acl_entry;
-- drop table acl_object_identity;
-- drop table acl_class;
-- drop table acl_sid;

CREATE TABLE acl_sid (
    id NUMBER(38) NOT NULL PRIMARY KEY,
    principal NUMBER(1) NOT NULL CHECK (principal in (0, 1)),
    sid NVARCHAR2(100) NOT NULL,
    CONSTRAINT unique_acl_sid UNIQUE (sid, principal)
);
CREATE SEQUENCE acl_sid_sequence START WITH 1 INCREMENT BY 1 NOMAXVALUE;
CREATE OR REPLACE TRIGGER acl_sid_id_trigger
    BEFORE INSERT ON acl_sid
    FOR EACH ROW
BEGIN
    SELECT acl_sid_sequence.nextval INTO :new.id FROM dual;
END;

CREATE TABLE acl_class (
    id NUMBER(38) NOT NULL PRIMARY KEY,
    class NVARCHAR2(100) NOT NULL,
    CONSTRAINT uk_acl_class UNIQUE (class)
);
CREATE SEQUENCE acl_class_sequence START WITH 1 INCREMENT BY 1 NOMAXVALUE;
CREATE OR REPLACE TRIGGER acl_class_id_trigger
    BEFORE INSERT ON acl_class
    FOR EACH ROW
BEGIN
    SELECT acl_class_sequence.nextval INTO :new.id FROM dual;
END;

CREATE TABLE acl_object_identity (
    id NUMBER(38) NOT NULL PRIMARY KEY,
    object_id_class NUMBER(38) NOT NULL,
    object_id_identity NVARCHAR2(36) NOT NULL,
    parent_object NUMBER(38),
    owner_sid NUMBER(38),
    entries_inheriting NUMBER(1) NOT NULL CHECK (entries_inheriting in (0, 1)),
    CONSTRAINT uk_acl_object_identity UNIQUE (object_id_class, object_id_identity),
    CONSTRAINT fk_acl_object_identity_parent FOREIGN KEY (parent_object) REFERENCES acl_object_identity (id),
    CONSTRAINT fk_acl_object_identity_class FOREIGN KEY (object_id_class) REFERENCES acl_class (id),
    CONSTRAINT fk_acl_object_identity_owner FOREIGN KEY (owner_sid) REFERENCES acl_sid (id)
);
CREATE SEQUENCE acl_object_identity_sequence START WITH 1 INCREMENT BY 1 NOMAXVALUE;
CREATE OR REPLACE TRIGGER acl_object_identity_id_trigger
    BEFORE INSERT ON acl_object_identity
    FOR EACH ROW
BEGIN
    SELECT acl_object_identity_sequence.nextval INTO :new.id FROM dual;
END;

CREATE TABLE acl_entry (
    id NUMBER(38) NOT NULL PRIMARY KEY,
    acl_object_identity NUMBER(38) NOT NULL,
    ace_order INTEGER NOT NULL,
    sid NUMBER(38) NOT NULL,
    mask INTEGER NOT NULL,
    granting NUMBER(1) NOT NULL CHECK (granting in (0, 1)),
    audit_success NUMBER(1) NOT NULL CHECK (audit_success in (0, 1)),
    audit_failure NUMBER(1) NOT NULL CHECK (audit_failure in (0, 1)),
    CONSTRAINT unique_acl_entry UNIQUE (acl_object_identity, ace_order),
    CONSTRAINT fk_acl_entry_object FOREIGN KEY (acl_object_identity) REFERENCES acl_object_identity (id),
    CONSTRAINT fk_acl_entry_acl FOREIGN KEY (sid) REFERENCES acl_sid (id)
);
CREATE SEQUENCE acl_entry_sequence START WITH 1 INCREMENT BY 1 NOMAXVALUE;
CREATE OR REPLACE TRIGGER acl_entry_id_trigger
    BEFORE INSERT ON acl_entry
    FOR EACH ROW
BEGIN
    SELECT acl_entry_sequence.nextval INTO :new.id FROM dual;
END;
