//! Liaison différée à la DLL WinFsp (feature `mount`).
fn main() {
    #[cfg(all(windows, feature = "mount"))]
    winfsp::build::winfsp_link_delayload();
}
