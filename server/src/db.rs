// Store a message with improved integrity protection
pub async fn store_message(
    pool: &PgPool,
    message_id: &[u8],
    recipient_key_hash: &[u8],
    encrypted_content: &[u8],
    hmac: &[u8],
    expiry_seconds: u64,
    priority: u8,
) -> Result<(), ServerError> {
    info!(
        "Storing message {} for recipient: {}",
        hex::encode(message_id),
        hex::encode(recipient_key_hash)
    );

    // Calculate expiry timestamp
    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(expiry_seconds);
    let expiry_timestamp = expiry
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Insert the message with added integrity protection
    sqlx::query(
        "INSERT INTO pending_messages 
         (id, recipient_key_hash, encrypted_content, hmac, created_at, expiry, is_delivered, priority, delivery_attempts) 
         VALUES ($1, $2, $3, $4, NOW(), to_timestamp($5), FALSE, $6, 0)"
    )
    .bind(message_id)
    .bind(recipient_key_hash)
    .bind(encrypted_content)
    .bind(hmac)
    .bind(expiry_timestamp as f64)
    .bind(priority as i16)
    .execute(pool)
    .await?;

    info!("Message stored successfully");
    Ok(())
}