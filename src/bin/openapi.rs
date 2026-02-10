//! Writes the fast-auth OpenAPI spec to `fast-auth/docs/openapi.yml`.

use fast_auth::openapi::openapi_yaml_write_default;

fn main() {
    match openapi_yaml_write_default() {
        Ok(path) => println!("OpenAPI spec written to {}", path.display()),
        Err(error) => {
            eprintln!("Failed to write OpenAPI spec: {error}");
            std::process::exit(1);
        }
    }
}
