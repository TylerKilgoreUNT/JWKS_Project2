use project1_rust::{build_routes, initialize_database, AppState, DB_FILE};

#[tokio::main]
async fn main() {
    // Initialize SQLite key storage before accepting requests.
    if let Err(err) = initialize_database(DB_FILE) {
        eprintln!("failed to initialize SQLite key store: {err}");
        std::process::exit(1);
    }

    // Build DB-backed routes and start the local HTTP server.
    let state = AppState::new(DB_FILE);
    let routes = build_routes(state);
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}
