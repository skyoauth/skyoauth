// Rebuild when a migration is added: `sqlx::migrate!` embeds the directory's
// files but cannot track new ones by itself.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
