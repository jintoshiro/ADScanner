# tests/test_sd.py
import uuid
from impacket.ldap import ldaptypes
from adscanner.utils.security_descriptor import extract_aces, find_dcsync_trustees

def make_sd(aces):
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = list(aces)
    sd['Dacl'] = acl
    return sd.getData()

def make_ace(sid, mask, object_type=None):
    nace = ldaptypes.ACE()
    nace['AceType'] = 0x05 if object_type else 0x00
    nace['AceFlags'] = 0
    
    if object_type:
        body = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        body['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        body['ObjectType'] = uuid.UUID(object_type).bytes_le
        body['InheritedObjectType'] = b''
    else:
        body = ldaptypes.ACCESS_ALLOWED_ACE()
        
    body['Mask'] = ldaptypes.ACCESS_MASK()
    body['Mask']['Mask'] = mask
    body['Sid'] = ldaptypes.LDAP_SID()
    body['Sid'].fromCanonical(sid)
    nace['Ace'] = body
    return nace

def test_dcsync_needs_both_rights():
    X = 'S-1-5-21-1-2-3-1105'
    Y = 'S-1-5-21-1-2-3-1106'
    GUID_GET_CHANGES = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    GUID_GET_CHANGES_ALL = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    
    raw = make_sd([
        make_ace(X, 0x100, object_type=GUID_GET_CHANGES),
        make_ace(X, 0x100, object_type=GUID_GET_CHANGES_ALL),
        make_ace(Y, 0x100, object_type=GUID_GET_CHANGES) # Y chỉ có 1 quyền
    ])
    
    aces = extract_aces(raw)
    trustees = find_dcsync_trustees(aces)
    
    assert X in trustees
    assert Y not in trustees