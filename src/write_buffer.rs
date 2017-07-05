use std::io::{self, Write};

pub struct WriteBuffer(Vec<u8>);

impl WriteBuffer {
    pub fn new() -> WriteBuffer {
        WriteBuffer(Vec::new())
    }

    pub fn done(self) -> Vec<u8> {
        self.0
    }
}

impl Write for WriteBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.extend(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
