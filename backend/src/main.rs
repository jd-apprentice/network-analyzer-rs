mod models;
mod network_scan;

use actix_cors::Cors;
use actix_web::{get, web, HttpResponse, HttpServer, Responder};
use models::Link;
use serde_json::json;

#[get("/api/scan/{subnet}")]
async fn scan_api_with_subnet(path: web::Path<String>) -> impl Responder {
    let subnet = path.into_inner();
    if let Some(topology) = network_scan::scan_network(Some(subnet)).await {
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
        json_response
    } else {
        let error_response = HttpResponse::InternalServerError().json(json!({
            "error": "Failed to scan network. Ensure you are connected and have necessary permissions."
        }));
        error_response
    }
}

#[get("/api/scan")]
async fn scan_api_default() -> impl Responder {
    if let Some(topology) = network_scan::scan_network(None).await {
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
        json_response
    } else {
        let error_response = HttpResponse::InternalServerError().json(json!({
            "error": "Failed to scan network. Ensure you are connected and have necessary permissions."
        }));
        error_response
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server started at http://localhost:8080");

    HttpServer::new(move || {
        let cors = Cors::permissive();

        actix_web::App::new()
            .wrap(cors)
            .service(scan_api_default)
            .service(scan_api_with_subnet)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
