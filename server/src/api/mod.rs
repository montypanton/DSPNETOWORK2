pub mod auth;
pub mod messages;
pub mod prekeys;
pub mod topics;

// Configure all API routes
pub fn configure(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.service(
        actix_web::web::scope("/api")
            // Authentication endpoints
            .service(auth::announce)
            .service(auth::refresh_token)
            .service(auth::ping)
            
            // Prekey endpoints
            .service(prekeys::upload_prekeys)
            .service(prekeys::get_prekeys)
            
            // Message endpoints
            .service(messages::send_message)
            .service(messages::get_messages)
            .service(messages::delete_message)
            
            // Topic endpoints
            .service(topics::create_topic)
            .service(topics::list_topics)
            .service(topics::subscribe_topic)
            .service(topics::unsubscribe_topic)
            .service(topics::publish_topic)
    );
}