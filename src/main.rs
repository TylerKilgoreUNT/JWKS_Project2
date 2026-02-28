use project1_rust::{build_routes, initialize_database, AppState, DB_FILE};

#[tokio::main]
async fn main() {
    initialize_database(DB_FILE).expect("failed to initialize SQLite key store");
    let state = AppState::new(DB_FILE);
    let routes = build_routes(state);
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}
