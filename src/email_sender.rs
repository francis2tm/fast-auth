//! Email sending abstraction for fast-auth.
//!
//! Implement [`EmailSender`] to provide email delivery for auth flows
//! like email verification and password reset.

use std::future::Future;
use thiserror::Error;

/// Error type for email sending operations.
#[derive(Debug, Clone, Error)]
pub enum EmailSendError {
    /// Failed to deliver email.
    #[error("email delivery failed: {0}")]
    DeliveryError(String),

    /// SMTP transport error.
    #[error("SMTP error: {0}")]
    SmtpError(String),
}

/// Trait for async email delivery.
///
/// Implement this to provide email functionality to fast-auth.
/// The default implementation (`()`) is a no-op that silently succeeds.
///
/// # Example
///
/// ```rust,ignore
/// use fast_auth::{EmailSender, EmailSendError};
///
/// #[derive(Clone)]
/// struct MyEmailService { /* ... */ }
///
/// impl EmailSender for MyEmailService {
///     async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), EmailSendError> {
///         // Queue or send email
///         Ok(())
///     }
/// }
/// ```
pub trait EmailSender: Send + Sync + Clone + 'static {
    /// Send an email asynchronously.
    ///
    /// Implementations may queue emails for background delivery or send immediately.
    fn send(
        &self,
        to: &str,
        subject: &str,
        body: &str,
    ) -> impl Future<Output = Result<(), EmailSendError>> + Send;
}

/// No-op email sender (default).
impl EmailSender for () {
    async fn send(&self, _to: &str, _subject: &str, _body: &str) -> Result<(), EmailSendError> {
        Ok(())
    }
}
