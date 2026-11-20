//! Liaison différée à la DLL WinFsp (feature `mount`) et icône de
//! l'exécutable (feature `tray`).
fn main() {
    #[cfg(all(windows, feature = "mount"))]
    winfsp::build::winfsp_link_delayload();
    #[cfg(all(windows, feature = "tray"))]
    {
        println!("cargo:rerun-if-changed=assets/s3m.rc");
        println!("cargo:rerun-if-changed=assets/s3m.ico");
        let _ = embed_resource::compile("assets/s3m.rc", embed_resource::NONE);
    }
}
