//! Verification email flows built on top of verification token primitives.

use crate::{
    Auth, AuthBackend, AuthHooks, AuthUser, EmailSender,
    error::AuthError,
    handlers::email::EMAIL_CONFIRM_PATH,
    tokens::{token_expiry_calculate, token_with_hash_generate},
    verification::{VerificationTokenType, verification_link_build},
};

/// Issue an email-confirmation token for a user and attempt to send the confirmation email.
///
/// Token persistence errors are returned to the caller.
/// Email delivery errors are logged and swallowed to avoid leaking account existence.
pub(crate) async fn email_confirm_send_for_user<
    B: AuthBackend,
    H: AuthHooks<B::User>,
    E: EmailSender,
>(
    auth: &Auth<B, H, E>,
    user: &B::User,
) -> Result<(), AuthError> {
    if user.email_confirmed_at().is_some() {
        return Ok(());
    }

    let config = auth.config();
    let email = user.email();

    // Generate token
    let (token, hash) = token_with_hash_generate();
    let expires_at = token_expiry_calculate(config.email_verification_token_expiry);

    // Store token
    auth.backend()
        .verification_token_issue(
            user.id(),
            &hash,
            VerificationTokenType::EmailConfirm,
            expires_at,
        )
        .await
        .map_err(AuthError::from_backend)?;

    // Build verification link
    let verify_link = verification_link_build(config, EMAIL_CONFIRM_PATH, &token);

    // Send email
    let subject = "Confirm your email address";
    let expires_in_seconds = config.email_verification_token_expiry.as_secs();
    let body = format!(
        "Please confirm your email address by clicking this link:\n\n{}\n\nThis link expires in {} seconds.",
        verify_link, expires_in_seconds
    );

    if let Err(e) = auth.email_sender().send(email, subject, &body).await {
        tracing::error!(error = ?e, "Failed to send confirmation email");
    }

    Ok(())
}
