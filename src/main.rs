use std::net::Ipv4Addr;
use std::str::FromStr;

// use fastly::handle::client_ip_addr;
use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use serde_json::json;

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::{Header, Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

const MIME_APPLICATION_DNS: &str = "application/dns-message";
const MIME_APPLICATION_JSON: &str = "application/json";

fn handle_debug() -> Result<Response, Error> {
    let debug_json = json!({
        "version": std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new()),
        "sid": std::env::var("FASTLY_SERVICE_ID").unwrap_or_else(|_| String::new()),
        "trace_id": std::env::var("FASTLY_TRACE_ID").unwrap_or_else(|_| String::new()),
    })
    .to_string();

    return Ok(Response::from_status(StatusCode::OK).with_body_text_plain(&debug_json));
}

fn handle_doh_get(req: Request) -> Result<Response, Error> {
    match req
        .get_query_parameter("dns")
        .and_then(|dns| base64::decode_config(dns, base64::URL_SAFE_NO_PAD).ok())
    {
        Some(query) => return handle_doh_request(query),
        _ => {
            return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                .with_body_text_plain("Missing or invalid 'dns' parameter\n"))
        }
    };
}

fn handle_doh_post(req: Request) -> Result<Response, Error> {
    handle_doh_request(req.into_body_bytes())
}

fn handle_doh_request(raw_msg: Vec<u8>) -> Result<Response, Error> {
    match handle_dns_request(raw_msg) {
        Ok(response) => Ok(Response::from_status(StatusCode::OK)
            .with_body_octet_stream(&response)
            .with_header(header::CONTENT_TYPE, MIME_APPLICATION_DNS)),
        _ => Ok(Response::from_status(StatusCode::BAD_REQUEST)
            .with_body_text_plain("Unable to parse DNS query\n")),
    }
}

fn handle_dns_request(raw_msg: Vec<u8>) -> Result<Vec<u8>, ProtoError> {
    println!("raw_msg: {:X?}", raw_msg);

    let request = Message::from_vec(&raw_msg)?;
    println!("request: {:?}", request);

    // at this point we have a well-formed DNS message so even in the
    // case of other errors we will be returning a DNS response.

    // only handle queries
    match (request.message_type(), request.op_code()) {
        (MessageType::Query, OpCode::Query) => (),
        _ => return dns_error(request, ResponseCode::NotImp).to_vec(),
    }

    // make sure we have one and only one query
    let query = match request.query() {
        Some(query) if request.queries().len() == 1 => query,
        _ => return dns_error(request, ResponseCode::FormErr).to_vec(),
    };
    println!("query: {:?}", query);

    return handle_dns_query(request.header(), query.clone()).to_vec();
}

fn handle_json_get(req: Request) -> Result<Response, Error> {
    let name = match req
        .get_query_parameter("name")
        .and_then(|name| Name::from_str_relaxed(name).ok())
    {
        Some(name) => name,
        _ => {
            return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                .with_body_text_plain("Missing or invalid 'name' parameter\n"))
        }
    };

    let rr_type = match req
        .get_query_parameter("type")
        .or(req.get_query_parameter("rr_type"))
        .and_then(|rr_type| RecordType::from_str(&rr_type.to_uppercase()).ok())
    {
        Some(rr_type) => rr_type,
        _ => {
            return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                .with_body_text_plain("Missing or invalid 'type' parameter\n"))
        }
    };

    // fake the header
    let response = handle_dns_query(&Header::new(), Query::query(name, rr_type));

    let json = json!({
        "Status": response.response_code().low(),
        "StatusMessage": response.response_code().to_str(),
        "TC": response.header().truncated(),
        "RD": response.header().recursion_desired(),
        "RA": response.header().recursion_available(),
        "AD": response.header().authoritative(),
        "CD": response.header().checking_disabled(),
        //"Question": response.queries(),
        "Answer": response.answers(),
        "Authority": response.name_servers(),
        "Additional": response.additionals(),
    })
    .to_string();

    return Ok(Response::from_status(StatusCode::OK)
        .with_body_text_plain(&json)
        .with_header(header::CONTENT_TYPE, MIME_APPLICATION_JSON));
}

fn handle_dns_query(req_header: &Header, query: Query) -> Message {
    let result = lookup(query.name().to_lowercase(), query.query_type());
    let response = dns_response(req_header, query, result);
    println!("response: {:?}", response);
    response
}

fn dns_error(request: Message, rcode: ResponseCode) -> Message {
    Message::error_msg(request.id(), request.op_code(), rcode)
}

fn dns_response(req_header: &Header, query: Query, result: LookupResult) -> Message {
    let mut header = Header::response_from_request(req_header);
    header.set_message_type(MessageType::Response);
    header.set_authoritative(true);

    let mut response = Message::new();
    response.set_header(header);
    response.add_query(query);

    response.set_response_code(result.rcode);
    response.insert_answers(result.answers);
    response.insert_name_servers(result.authority);
    response.insert_additionals(result.additionals);

    response
}

struct LookupResult {
    rcode: ResponseCode,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additionals: Vec<Record>,
}

fn lookup(name: Name, rr_type: RecordType) -> LookupResult {
    println!("lookup {}:{}", name, rr_type);
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

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    match (
        req.get_method(),
        req.get_path(),
        req.get_header_str(header::CONTENT_TYPE),
    ) {
        (&Method::GET, "/dns-query", Some(MIME_APPLICATION_DNS)) => handle_doh_get(req),
        (&Method::POST, "/dns-query", Some(MIME_APPLICATION_DNS)) => handle_doh_post(req),

        (&Method::GET, "/resolve", ..) => handle_json_get(req),
        (&Method::GET, "/query", ..) => {
            return Ok(
                Response::from_status(StatusCode::OK).with_body_text_plain("TODO html form\n")
            )
        }

        (&Method::GET, "/debug", ..) => handle_debug(),

        _ => {
            // Catch all other requests and return a 404.
            return Ok(
                Response::from_status(StatusCode::NOT_FOUND).with_body_text_plain("Not Found\n")
            );
        }
    }
}
