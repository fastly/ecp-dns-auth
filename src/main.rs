use std::net::Ipv4Addr;

use fastly::handle::client_ip_addr;
use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use serde_json::json;

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

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
        _ => {
            return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                .with_body_text_plain("Missing or invalid query string\n"))
        }
    };
    handle_doh_request(query)
}

fn handle_doh_post(req: Request) -> Result<Response, Error> {
    handle_doh_request(req.into_body_bytes())
}

fn handle_doh_request(raw_msg: Vec<u8>) -> Result<Response, Error> {
    match handle_request(raw_msg) {
        Ok(response) => Ok(Response::from_status(StatusCode::OK)
            .with_body_octet_stream(&response)
            .with_header(header::CONTENT_TYPE, "application/dns-message")),
        _ => Ok(Response::from_status(StatusCode::BAD_REQUEST)
            .with_body_text_plain("Unable to parse DNS query\n")),
    }
}

fn dns_error(request: Message, rcode: ResponseCode) -> Result<Vec<u8>, ProtoError> {
    Message::error_msg(request.id(), request.op_code(), ResponseCode::FormErr).to_vec()
}

struct LookupResult {
    rcode: ResponseCode,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additionals: Vec<Record>,
}

fn lookup(name: Name, rr_type: RecordType) -> LookupResult {
    let answer = Record::from_rdata(name, 5, RData::A(Ipv4Addr::new(93, 184, 216, 34)));
    let answers = vec![answer];

    let result = LookupResult {
        rcode: ResponseCode::NoError,
        answers: answers,
        authority: Vec::new(),
        additionals: Vec::new(),
    };
    return result;
}

fn handle_request(raw_msg: Vec<u8>) -> Result<Vec<u8>, ProtoError> {
    println!("raw_msg: {:X?}", raw_msg);

    let mut request = Message::from_vec(&raw_msg)?;
    println!("request: {:?}", request);

    // at this point we have a well-formed DNS message so even in the
    // case of other errors we will be returning a DNS response.

    // only handle queries
    match (request.message_type(), request.op_code()) {
        (MessageType::Query, OpCode::Query) => (),
        _ => return dns_error(request, ResponseCode::NotImp),
    }

    // make sure we have one and only one query
    let query = match request.query() {
        Some(query) if request.queries().len() == 1 => query,
        _ => return dns_error(request, ResponseCode::FormErr),
    };
    println!("query: {:?}", query);

    // build the base response
    let mut response_header = Header::response_from_request(request.header());
    response_header.set_authoritative(true);
    let mut response = Message::new();
    response.set_header(response_header);
    response.add_query(query.clone());

    // do the lookup
    let result = lookup(query.name().to_lowercase(), query.query_type());

    // update and send the response
    response.set_response_code(result.rcode);
    response.insert_answers(result.answers);
    response.insert_name_servers(result.authority);
    response.insert_additionals(result.additionals);
    println!("response: {:?}", response);

    return response.to_vec();
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
