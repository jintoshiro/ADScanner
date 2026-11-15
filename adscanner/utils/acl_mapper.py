"""
Ánh xạ quyền (Mask) chuẩn xác theo Microsoft Access Mask.
"""
GUID_FORCE_CHANGE_PWD = '00299570-246d-11d0-a768-00aa006e0529'
GUID_MEMBER           = 'bf9679c0-0de6-11d0-a285-00aa003049e2' # Thuộc tính member của Group
GUID_DCSYNC_1         = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' # Get-Changes
GUID_DCSYNC_2         = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' # Get-Changes-All

# Bitmask
GENERIC_ALL      = 0x10000000
FULL_CONTROL     = 0x000F01FF
WRITE_DACL       = 0x00040000
WRITE_OWNER      = 0x00080000
WRITE_PROP       = 0x00000020
CONTROL_ACCESS   = 0x00000100

def classify_ace(ace: dict, target_type: str) -> list[str]:
    """
    Trả về danh sách các quyền thực tế mà ACE này cấp.
    """
    mask = ace.get('mask', 0)
    ot = ace.get('object_type')
    rels = []

    # 1. Kiểm tra GenericAll / Full Control
    if (mask & GENERIC_ALL) or ((mask & FULL_CONTROL) == FULL_CONTROL):
        return ['GenericAll'] # Toàn quyền thì không cần xét các quyền lẻ tẻ khác

    # 2. Các quyền riêng lẻ
    if mask & WRITE_DACL:  rels.append('WriteDacl')
    if mask & WRITE_OWNER: rels.append('WriteOwner')
    
    if mask & WRITE_PROP:
        if ot is None:
            rels.append('GenericWrite') # Ghi mọi thuộc tính
        elif ot == GUID_MEMBER and target_type == 'group':
            rels.append('AddMember')
            
    if mask & CONTROL_ACCESS:
        if ot is None:
            rels.append('AllExtendedRights')
        elif ot == GUID_FORCE_CHANGE_PWD and target_type == 'user':
            rels.append('ForceChangePassword')
        elif ot in (GUID_DCSYNC_1, GUID_DCSYNC_2) and target_type == 'domain':
            rels.append('DCSync')

    return rels