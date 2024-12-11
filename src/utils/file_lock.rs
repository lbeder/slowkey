use fs2::FileExt;
use std::fs::File;
use std::io::{self};
use std::path::Path;

pub struct FileLock {
    file: File,
}

impl FileLock {
    #[allow(dead_code)]
    pub fn lock<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;

        file.lock_exclusive()?;

        Ok(FileLock { file })
    }

    pub fn try_lock<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;

        file.try_lock_exclusive()?;

        Ok(FileLock { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
