mod models;
mod network_scan;

use actix_cors::Cors;
use actix_files::Files;
use actix_web::{get, HttpResponse, HttpServer, Responder};
use models::Link;
use network_scan::scan_network;
use serde_json::json;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(include_str!("../static/index.html"))
}

#[get("/api/scan")]
async fn scan_api() -> impl Responder {
    if let Some(topology) = scan_network().await {
        let gateway_ip = topology.gateway.clone();

        let mut links = Vec::new();
        for device in &topology.devices {
            if device.ip != gateway_ip {
                links.push(Link {
                    source: device.ip.to_string(),
                    target: gateway_ip.to_string(),
                    value: 1.0,
                });
            }
        }

        let mut mutable_topology = topology.clone();
        mutable_topology.links = Some(links);
        let json_response = HttpResponse::Ok().json(mutable_topology);
        println!("Server sending success response: {:?}", json_response);
        json_response
    } else {
        let error_response = HttpResponse::InternalServerError().json(json!({
            "error": "Failed to scan network. Ensure you are connected and have necessary permissions."
        }));
        println!("Server sending error response: {:?}", error_response);
        error_response
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Servidor iniciado en http://localhost:8080");
    println!("📡 Abre tu navegador y accede a la URL para escanear tu red");

    HttpServer::new(move || {
        let cors = Cors::permissive();

        actix_web::App::new()
            .wrap(cors)
            .service(index) // Serve index.html directly
            .service(Files::new("/static", "./static")) // Serve other static files from /static/
            .service(scan_api)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
