-- Not required. Just shows the sort of queries being sent to DB.


select  acl_object_identity.object_id_identity,
        acl_entry.ace_order,
        acl_object_identity.id as acl_id,
        acl_object_identity.parent_object,
        acl_object_identity,
        entries_inheriting,
        acl_entry.id as ace_id,
        acl_entry.mask,
        acl_entry.granting,
        acl_entry.audit_success,
        acl_entry.audit_failure,
        acl_sid.principal as ace_principal,
        acl_sid.sid as ace_sid,
        acli_sid.principal as acl_principal,
        acli_sid.sid as acl_sid,
        acl_class.class

from    acl_object_identity,
        acl_sid acli_sid,
        acl_class

left join acl_entry on acl_object_identity.id = acl_entry.acl_object_identity
left join acl_sid on acl_entry.sid = acl_sid.id

where
    acli_sid.id = acl_object_identity.owner_sid

and acl_class.id = acl_object_identity.object_id_class

and (

    (acl_object_identity.object_id_identity = 1 and acl_class.class = 'sample.contact.contact')
or
    (acl_object_identity.object_id_identity = 2000 and acl_class.class = 'sample.contact.contact')

) order by acl_object_identity.object_id_identity asc, acl_entry.ace_order asc
