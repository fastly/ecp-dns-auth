use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    match req.get_header_str("content-type") {
        // Handle DoH requests
        Some("application/dns-message") => match req.get_method() {
            &Method::GET => {
                println!("DoH GET");
                return Ok(Response::from_status(StatusCode::OK)
                    .with_body_text_plain("GET application/dns-message\n"));
            }

            &Method::POST => {
                return Ok(Response::from_status(StatusCode::OK)
                    .with_body_text_plain("POST application/dns-message\n"))
            }

            _ => {
                return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                    .with_header(header::ALLOW, "GET, POST")
                    .with_body_text_plain("Use GET/POST with DoH\n"))
            }
        },

        // Handle json/html requests
        _ => match (req.get_method(), req.get_path()) {
            (&Method::GET, "/resolve") => {
                return Ok(Response::from_status(StatusCode::OK).with_body_text_plain("TODO json\n"))
            }

            (&Method::GET, "/query") => {
                return Ok(
                    Response::from_status(StatusCode::OK).with_body_text_plain("TODO html form\n")
                )
            }

            _ => {
                // Catch all other requests and return a 404.
                return Ok(Response::from_status(StatusCode::NOT_FOUND)
                    .with_body_text_plain("Not Found\n"));
            }
        },
    };
}
