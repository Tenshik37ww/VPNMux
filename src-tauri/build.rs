fn main() {
    let attrs = tauri_build::Attributes::new();
    // Windows: приложение требует прав администратора (создание TUN/служб, маршруты)
    #[cfg(windows)]
    let attrs = attrs.windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest")),
    );
    tauri_build::try_build(attrs).expect("tauri build");
}
