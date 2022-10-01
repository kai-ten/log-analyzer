use actix_web::dev::Server;
use actix_web::{web, get, App, HttpServer, Responder, HttpResponse, error, Error};
use std::collections::HashMap;
use actix_web::http::StatusCode;
use serde_json::{json, Value};
use serde::{Deserialize, Serialize};
use sigma_rule_parser::structs::detection::Detection;
use futures_util::StreamExt as _;

// curl -X GET \
// -H "Content-Type: application/json" \
// -d '{ "fname": "Angus", "lname": "Chuck"}' \
// http://localhost:8080/v1/log-ingress


#[derive(Serialize, Deserialize, Debug)]
struct Log {

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

// fn testies() {
//     let swag: Log = json!({
//         "code": 200,
//         "success": true,
//         "payload": {
//             "features": [
//                 "serde",
//                 "json"
//             ]
//         }
//     });
//
//     println!("{:?}", swag);
// }

const MAX_SIZE: usize = 262_144;

#[get("/log-ingress")]
async fn handle_log(mut payload: web::Payload, mappings: web::Data<Vec<Detection>>) -> Result<HttpResponse, Error> {
    // println!("Raw Json 'Value': {:?}", payload.);
    println!("Mappings (req): {:?}", mappings);
    // log['key'] is a borrow of data at that index
    // json map can be indexed with string keys
    // json array can be indexed with int keys

    // If the type of the data is not right for the type with
    // which it is being indexed, or if a map does not contain the
    // key being indexed, or if the index into a vector is out of bounds,
    // the returned element is Value::Null.

    // String - we have the key and value
    // Map - We have a nested set of key + values
    // Array - We have a list of values

    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
            return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk);
    }


    Ok(HttpResponse::new(StatusCode::OK)) // <- send response

}



pub fn create_server() -> Server {
    let detections: Vec<Detection> = vec![];
    let server = match HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(detections.clone()))
            .service(handle_log)
    })
        .bind(("127.0.0.1", 8080)) {
        Ok(server) => server,
        Err(_) => todo!()
    };

    server.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        http::{self, header::ContentType},
        test
    };

    #[actix_web::test]
    async fn test_index_ok() {
        let detections = vec![0, 1];
        let app = test::init_service(
            App::new()
                .app_data(detections.clone())
                .service(handle_log)
        ).await;

        let req = test::TestRequest::get()
            .uri("/v1/log-ingress")
            .to_request();
        println!("Request: {:?}", req);

        let resp = test::call_service(&app, req).await;

        println!("Response: {:?}", resp);
        // assert_eq!(resp.status(), http::StatusCode::OK);
    }


}
