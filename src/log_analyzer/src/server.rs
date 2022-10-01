use actix_web::dev::Server;
use actix_web::{web, App, HttpServer, Responder};
use std::collections::HashMap;

// curl -X GET \
// -H "Content-Type: application/json" \
// -d '{ "fname": "Angus", "lname": "Chuck"}' \
// http://localhost:8080/v1/log-ingress

async fn handle_log(log: web::Json<serde_json::Value>) -> impl Responder {
    println!("Raw Json 'Value': {:?}", log);
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

    println!("Accessing: {:?}", log[0]);
    log
}

pub fn create_server() -> Server {
    let server = match HttpServer::new(|| {
        App::new().service(web::scope("/v1").route("/log-ingress", web::get().to(handle_log)))
    })
    .bind(("127.0.0.1", 8080))
    {
        Ok(server) => server,
        Err(_) => todo!(),
    };

    server.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        http::{self, header::ContentType},
        test,
    };

    // #[actix_web::test]
    // async fn test_index_ok() {
    //     let req = test::TestRequest::default()
    //         .insert_header(ContentType::plaintext())
    //         .to_http_request();
    //     let resp = index().await;
    //     assert_eq!(resp.status(), http::StatusCode::OK);
    // }
    //
    // #[actix_web::test]
    // async fn test_index_not_ok() {
    //     let req = test::TestRequest::default().to_http_request();
    //     let resp = index().await;
    //     assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    // }
}
