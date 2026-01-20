//! Authentication handlers.

pub mod email;
pub mod me;
pub mod password;
pub mod sign_in;
pub mod sign_out;
pub mod sign_up;

pub use email::{EMAIL_CONFIRM_PATH, EMAIL_CONFIRM_SEND_PATH, email_confirm_routes};
pub use me::{ME_PATH, me_routes};
pub use password::{PASSWORD_FORGOT_PATH, PASSWORD_RESET_PATH, password_reset_routes};
pub use sign_in::{SIGN_IN_PATH, sign_in_routes};
pub use sign_out::{SIGN_OUT_PATH, sign_out_routes};
pub use sign_up::{SIGN_UP_PATH, sign_up_routes};
