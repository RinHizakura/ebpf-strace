pub struct SyscallDesc {
    pub id: u64,
    pub name: &'static str,
}

impl SyscallDesc {
    pub fn new(id: u64, name: &'static str) -> Self {
        SyscallDesc { id, name }
    }
}
