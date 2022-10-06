use fastly::error::anyhow;
use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use serde_json::json;

fn debug_json() -> String {
    json!({
        "version": std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new()),
        "sid": std::env::var("FASTLY_SERVICE_ID").unwrap_or_else(|_| String::new()),
        "trace_id": std::env::var("FASTLY_TRACE_ID").unwrap_or_else(|_| String::new()),
    })
    .to_string()
}

fn query_from_qstring(req: Request) -> Option<Vec<u8>> {
    let question_str = req.get_query_parameter("dns");
    let query = match question_str
        .and_then(|question_str| base64::decode_config(question_str, base64::URL_SAFE_NO_PAD).ok())
    {
        Some(query) => query,
        _ => return None,
    };
    Some(query)
}

fn handle_doh_get(req: Request) -> Result<Response, Error> {
    let query = match query_from_qstring(req) {
        Some(query) => query,
        _ => return Err(anyhow!("bad query string")),
    };

    handle_doh_query(query)
}

fn handle_doh_post(req: Request) -> Result<Response, Error> {
    handle_doh_query(req.into_body_bytes())
}

fn handle_doh_query(query: Vec<u8>) -> Result<Response, Error> {
    println!("query: {:X?}", query);
    // return Ok(Response::from_status(StatusCode::OK).with_body_text_plain("DoH query response\n"));
    return Ok(Response::from_status(StatusCode::OK)
        .with_body_octet_stream(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x1C, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x0E,
            0x7D, 0x00, 0x10, 0x20, 0x01, 0x0D, 0xB8, 0xAB, 0xCD, 0x00, 0x12, 0x00, 0x01, 0x00,
            0x02, 0x00, 0x03, 0x00, 0x04,
        ])
        .with_header(header::CONTENT_TYPE, "application/dns-message"));
}

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    match (
        req.get_method(),
        req.get_path(),
        req.get_header_str(header::CONTENT_TYPE),
    ) {
        (&Method::GET, "/dns-query", Some("application/dns-message")) => handle_doh_get(req),
        (&Method::POST, "/dns-query", Some("application/dns-message")) => handle_doh_post(req),

        (&Method::GET, "/resolve", ..) => {
            return Ok(Response::from_status(StatusCode::OK).with_body_text_plain("TODO json\n"))
        }

        (&Method::GET, "/query", ..) => {
            return Ok(
                Response::from_status(StatusCode::OK).with_body_text_plain("TODO html form\n")
            )
        }

        (&Method::GET, "/debug", ..) => {
            return Ok(Response::from_status(StatusCode::OK).with_body_text_plain(&debug_json()))
        }

        _ => {
            // Catch all other requests and return a 404.
            return Ok(Response::from_status(StatusCode::NOT_FOUND)
                .with_header("x-dns-auth-debug", debug_json())
                .with_body_text_plain("Not Found\n"));
        }
    }
}
