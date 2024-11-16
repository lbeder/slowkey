use libsodium_sys::sodium_init;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn initialize() {
    INIT.call_once(|| unsafe {
        let res = sodium_init();
        if res != 0 {
            panic!("sodium_init failed with: {res}");
        }
    });
}
